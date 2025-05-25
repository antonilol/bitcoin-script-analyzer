mod bytes;
mod op;
mod opcode;
mod stack;

pub use self::{
    bytes::BytesExprBox,
    op::{MultisigArgs, OpExpr, OpExprArgs},
    opcode::{Opcode1, Opcode2, Opcode3},
    stack::StackExpr,
};
use crate::{
    context::{ScriptContext, ScriptRules, ScriptVersion},
    script::convert::{
        check_int, decode_bool, decode_int_unchecked, encode_bool_expr, encode_int_expr,
    },
    script_error::ScriptError,
    util::checksig::{
        check_pub_key, is_valid_signature_encoding, PubKeyCheckResult, SIG_HASH_TYPES,
    },
};
use bitcoin_hashes::{ripemd160, sha1, sha256};
use core::{cmp::Ordering, fmt, mem::replace};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Op(OpExpr),
    Stack(StackExpr),
    Bytes(BytesExprBox),
}

impl Expr {
    pub fn stack(pos: u32) -> Self {
        Self::Stack(StackExpr::new(pos))
    }

    pub fn bytes(bytes: &[u8]) -> Self {
        Self::Bytes(BytesExprBox::new(bytes.into()))
    }

    pub fn bytes_owned(bytes: Box<[u8]>) -> Self {
        Self::Bytes(BytesExprBox::new(bytes))
    }

    pub fn priority(&self) -> impl Ord {
        match self {
            Expr::Bytes(_) => 0u8,
            Expr::Stack(_) => 1,
            Expr::Op(_) => 2,
        }
    }

    /// Used with [`replace`] instead of [`take`] because implementing [`Default`] and returning
    /// this does not make sense.
    ///
    /// [`replace`]: core::mem::replace
    /// [`take`]: core::mem::take
    pub fn valid_garbage() -> Self {
        Self::Stack(StackExpr::new(u32::MAX))
    }

    pub fn sort_recursive(exprs: &mut [Expr]) {
        Self::sort_recursive_(exprs, true);
    }

    pub fn sort_recursive_(exprs: &mut [Expr], sort_current: bool) {
        if sort_current {
            exprs.sort_unstable();
        }
        for expr in exprs {
            if let Self::Op(expr) = expr {
                let sort_next = expr.opcode().can_reorder_args();
                Self::sort_recursive_(expr.args_mut(), sort_next);
            }
        }
    }

    pub fn eval(&mut self, ctx: ScriptContext) -> Result<bool, ScriptError> {
        self.eval_(ctx, 0)
    }

    fn eval_(&mut self, ctx: ScriptContext, depth: usize) -> Result<bool, ScriptError> {
        let mut changed = false;
        if let Expr::Op(ref mut op) = self {
            for arg in op.args_mut() {
                changed |= arg.eval_(ctx, depth + 1)?;
            }
            match &mut op.args {
                OpExprArgs::Args1(op, args) => {
                    let arg = &mut args[0];
                    match op {
                        Opcode1::OP_SIZE => {
                            match arg {
                                Expr::Bytes(b) => {
                                    *self = encode_int_expr(b.len() as i64);
                                    return Ok(true);
                                }
                                Expr::Op(op) if op.opcode().returns_boolean() => {
                                    *self = replace(arg, Self::valid_garbage());
                                    return Ok(true);
                                }
                                _ => {}
                            };
                        }

                        Opcode1::OP_RIPEMD160 | Opcode1::OP_SHA1 | Opcode1::OP_SHA256 => {
                            if let Expr::Bytes(b) = arg {
                                let data = b.as_ref();

                                let hash: Box<[u8]> = match op {
                                    Opcode1::OP_RIPEMD160 => {
                                        Box::new(ripemd160::Hash::hash(data).to_byte_array())
                                    }
                                    Opcode1::OP_SHA1 => {
                                        Box::new(sha1::Hash::hash(data).to_byte_array())
                                    }
                                    Opcode1::OP_SHA256 => {
                                        Box::new(sha256::Hash::hash(data).to_byte_array())
                                    }
                                    _ => unreachable!(),
                                };

                                *self = Expr::bytes_owned(hash);
                                return Ok(true);
                            }
                        }

                        Opcode1::OP_INTERNAL_NOT | Opcode1::OP_NOT => {
                            if let Expr::Bytes(arg) = arg {
                                return if *op == Opcode1::OP_NOT && arg.len() > 4 {
                                    Err(ScriptError::SCRIPT_ERR_NUM_OVERFLOW)
                                } else {
                                    *self = encode_bool_expr(!decode_bool(arg));
                                    Ok(true)
                                };
                            }
                            if let Expr::Op(arg) = arg {
                                if let OpExprArgs::Args1(op, arg) = &arg.args {
                                    if (*op == Opcode1::OP_NOT || *op == Opcode1::OP_INTERNAL_NOT)
                                        && match &arg[0] {
                                            Expr::Op(op) => op.opcode().returns_boolean(),
                                            Expr::Stack(_) => depth == 0,
                                            _ => false,
                                        }
                                    {
                                        *self = arg[0].clone();
                                        return Ok(true);
                                    }
                                }
                            }
                            if let Expr::Op(arg) = arg {
                                if depth == 0 && ctx.rules == ScriptRules::All {
                                    if let OpExprArgs::Args2(Opcode2::OP_CHECKSIG, args) = &arg.args
                                    {
                                        // assumes valid pubkey TODO fix
                                        *self = Opcode2::OP_EQUAL.expr(Box::new([
                                            args[0].clone(),
                                            encode_bool_expr(false),
                                        ]));
                                        return Ok(true);
                                    }
                                }
                            }
                        }

                        _ => {}
                    }
                }

                OpExprArgs::Args2(op, args) => {
                    match op {
                        Opcode2::OP_ADD | Opcode2::OP_SUB => {
                            let [ref a1, ref a2] = **args;
                            if let Expr::Bytes(a1) = a1 {
                                check_int(a1, 4)?;
                            }
                            if let Expr::Bytes(a2) = a2 {
                                check_int(a2, 4)?;
                            }
                            if let (Expr::Bytes(a1), Expr::Bytes(a2)) = (a1, a2) {
                                let a = decode_int_unchecked(a1);
                                let b = decode_int_unchecked(a2);
                                *self = encode_int_expr(match op {
                                    Opcode2::OP_ADD => a + b,
                                    _ => a - b,
                                });
                                return Ok(true);
                            }
                        }

                        Opcode2::OP_EQUAL => {
                            let [ref a1_, ref a2] = **args;
                            match (a1_, a2) {
                                (Expr::Bytes(a1), Expr::Bytes(a2)) => {
                                    *self = encode_bool_expr(a1 == a2);
                                    return Ok(true);
                                }
                                (Expr::Op(a1), Expr::Bytes(a2)) => {
                                    if a1.opcode().returns_boolean() {
                                        if a2.is_true() {
                                            *self = a1_.clone()
                                        } else if a2.is_false() {
                                            *self = Opcode1::OP_NOT.expr(Box::new([a1_.clone()]))
                                        } else {
                                            *self = encode_bool_expr(false)
                                        }
                                        return Ok(true);
                                    }
                                }
                                _ => {}
                            }
                        }

                        Opcode2::OP_CHECKSIG => {
                            let [ref sig, ref pubkey] = **args;
                            if ctx.version == ScriptVersion::SegwitV1 {
                                if let Expr::Bytes(pubkey) = pubkey {
                                    if pubkey.len() == 0 {
                                        return Err(ScriptError::SCRIPT_ERR_PUBKEYTYPE);
                                    } else if pubkey.len() != 32 {
                                        return if ctx.rules == ScriptRules::All {
                                            Err(ScriptError::SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE)
                                        } else {
                                            *self = encode_bool_expr(true);
                                            Ok(true)
                                        };
                                    }
                                    if let Expr::Bytes(sig) = sig {
                                        if sig.len() == 0 {
                                            *self = encode_bool_expr(false);
                                            return Ok(true);
                                        } else if sig.len() != 64 && sig.len() != 65 {
                                            return Err(ScriptError::SCRIPT_ERR_SCHNORR_SIG_SIZE);
                                        } else if sig.len() == 65
                                            && !SIG_HASH_TYPES.contains(&sig[64])
                                        {
                                            return Err(
                                                ScriptError::SCRIPT_ERR_SCHNORR_SIG_HASHTYPE,
                                            );
                                        }
                                    }
                                }
                            } else if let Expr::Bytes(pubkey) = pubkey {
                                // TODO CheckPubKeyEncoding without SCRIPT_VERIFY_STRICTENC?
                                match check_pub_key(pubkey) {
                                    PubKeyCheckResult::Invalid => {
                                        return Err(ScriptError::SCRIPT_ERR_PUBKEYTYPE);
                                    }
                                    PubKeyCheckResult::Valid { compressed } => {
                                        if !compressed
                                            && ctx.version == ScriptVersion::SegwitV0
                                            && ctx.rules == ScriptRules::All
                                        {
                                            return Err(ScriptError::SCRIPT_ERR_WITNESS_PUBKEYTYPE);
                                        }
                                    }
                                }
                                if let Expr::Bytes(sig) = sig {
                                    if sig.len() == 0 {
                                        *self = encode_bool_expr(false);
                                        return Ok(true);
                                    }
                                    if ctx.rules == ScriptRules::All {
                                        // TODO low s
                                        if !is_valid_signature_encoding(sig) {
                                            return Err(ScriptError::SCRIPT_ERR_SIG_DER);
                                        } else if !SIG_HASH_TYPES.contains(&sig[sig.len() - 1]) {
                                            return Err(ScriptError::SCRIPT_ERR_SIG_HASHTYPE);
                                        }
                                    }
                                }
                            }
                        }

                        _ => {}
                    }
                }

                OpExprArgs::Args3(_, _) => {}

                OpExprArgs::Multisig(m) => {
                    if m.keys().len() == m.sigs().len() {
                        let (sigs, pks) = replace(m, MultisigArgs::valid_garbage()).into_vecs();

                        *self = sigs
                            .into_iter()
                            .zip(pks)
                            .map(|(sig, pk)| Opcode2::OP_CHECKSIG.expr(Box::new([sig, pk])))
                            .reduce(|a, b| Opcode2::OP_BOOLAND.expr(Box::new([a, b])))
                            .unwrap_or_else(|| encode_bool_expr(true));

                        return Ok(true);
                    }
                    // TODO check pubkeys, sigs like with checksig, maybe cache check results to
                    // not repeat them multiple times
                }
            }
        }

        Ok(changed)
    }

    pub fn replace_all(&mut self, search: &Expr, replace: &Expr) -> bool {
        if search == self {
            *self = replace.clone();
            true
        } else if let Expr::Op(ref mut op) = self {
            let mut changed = false;
            for arg in op.args_mut() {
                changed |= arg.replace_all(search, replace);
            }
            changed
        } else {
            false
        }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Op(e) => write!(f, "{e}"),
            Expr::Stack(e) => write!(f, "{e}"),
            Expr::Bytes(e) => write!(f, "{e}"),
        }
    }
}

impl PartialOrd for Expr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Expr {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Op(a), Self::Op(b)) => a.cmp(b),
            (Self::Stack(a), Self::Stack(b)) => a.cmp(b),
            (Self::Bytes(a), Self::Bytes(b)) => a.cmp(b),
            (a, b) => b.priority().cmp(&a.priority()),
        }
    }
}
