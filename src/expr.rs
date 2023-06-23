use crate::{
    context::{ScriptContext, ScriptRules, ScriptVersion},
    opcode::{opcodes, Opcode},
    script::convert::{
        check_int, decode_bool, decode_int_unchecked, encode_bool, encode_int, FALSE, TRUE,
    },
    script_error::ScriptError,
    util::checksig::{
        check_pub_key, is_valid_signature_encoding, PubKeyCheckResult, SIG_HASH_TYPES,
    },
};
use bitcoin_hashes::{ripemd160, sha1, sha256, Hash};
use core::{cmp::Ordering, fmt, mem::replace, ops::Deref};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Op(OpExpr),
    Stack(StackExpr),
    Bytes(BytesExpr),
}

impl Expr {
    pub fn stack(pos: u32) -> Self {
        Self::Stack(StackExpr {
            pos,
            //data: ExprData::new(),
        })
    }

    pub fn bytes(bytes: &[u8]) -> Self {
        Self::Bytes(BytesExpr(bytes.to_vec().into_boxed_slice()))
    }

    pub fn bytes_owned(bytes: Box<[u8]>) -> Self {
        Self::Bytes(BytesExpr(bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Opcode1 {
    OP_SIZE = 0x82,

    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,

    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,

    OP_INTERNAL_NOT = 0xfe,
}

impl Opcode1 {
    pub fn expr(self, arg: Box<[Expr; 1]>) -> Expr {
        Expr::Op(OpExpr::new(OpExprArgs::Args1(self, arg), None))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Opcode2 {
    OP_EQUAL = 0x87,

    OP_ADD = 0x93,
    OP_SUB = 0x94,

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,

    OP_CHECKSIG = 0xac,
}

impl Opcode2 {
    pub fn expr(self, args: Box<[Expr; 2]>) -> Expr {
        Expr::Op(OpExpr::new(OpExprArgs::Args2(self, args), None))
    }

    pub fn expr_with_error(self, args: Box<[Expr; 2]>, error: ScriptError) -> Expr {
        Expr::Op(OpExpr::new(OpExprArgs::Args2(self, args), Some(error)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Opcode3 {
    OP_WITHIN = 0xa5,
}

impl Opcode3 {
    pub fn expr(self, args: Box<[Expr; 3]>) -> Expr {
        Expr::Op(OpExpr::new(OpExprArgs::Args3(self, args), None))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigArgs {
    exprs: Box<[Expr]>,
    pk_offset: usize,
}

impl MultisigArgs {
    pub fn expr(exprs: Box<[Expr]>, pk_offset: usize) -> Expr {
        Expr::Op(OpExpr::new(
            OpExprArgs::Multisig(Self { exprs, pk_offset }),
            None,
        ))
    }

    /// Used with [`replace`] instead of [`take`] because implementing [`Default`] and returning
    /// this does not make sense.
    ///
    /// [`replace`]: core::mem::replace
    /// [`take`]: core::mem::take
    pub fn valid_garbage() -> Self {
        Self {
            exprs: Box::new([]),
            pk_offset: 0,
        }
    }
}

impl MultisigArgs {
    pub fn sigs(&self) -> &[Expr] {
        &self.exprs[..self.pk_offset]
    }

    pub fn keys(&self) -> &[Expr] {
        &self.exprs[self.pk_offset..]
    }

    pub fn into_vecs(self) -> (Vec<Expr>, Vec<Expr>) {
        let mut sigs = self.exprs.into_vec();
        let pks = sigs.split_off(self.pk_offset);

        (sigs, pks)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpExprArgs {
    Args1(Opcode1, Box<[Expr; 1]>),
    Args2(Opcode2, Box<[Expr; 2]>),
    Args3(Opcode3, Box<[Expr; 3]>),
    Multisig(MultisigArgs),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpExpr {
    pub args: OpExprArgs,
    error: Option<ScriptError>,
    //data: ExprData,
}

impl OpExpr {
    pub fn new(args: OpExprArgs, error: Option<ScriptError>) -> Self {
        Self { args, error }
    }

    pub fn opcode(&self) -> Opcode {
        Opcode {
            opcode: match self.args {
                OpExprArgs::Args1(op, _) => op as u8,
                OpExprArgs::Args2(op, _) => op as u8,
                OpExprArgs::Args3(op, _) => op as u8,
                OpExprArgs::Multisig(_) => return opcodes::OP_CHECKMULTISIG,
            },
        }
    }

    pub fn args(&self) -> &[Expr] {
        match &self.args {
            OpExprArgs::Args1(_, args) => &**args,
            OpExprArgs::Args2(_, args) => &**args,
            OpExprArgs::Args3(_, args) => &**args,
            OpExprArgs::Multisig(m) => &m.exprs,
        }
    }

    pub fn args_mut(&mut self) -> &mut [Expr] {
        match &mut self.args {
            OpExprArgs::Args1(_, args) => &mut **args,
            OpExprArgs::Args2(_, args) => &mut **args,
            OpExprArgs::Args3(_, args) => &mut **args,
            OpExprArgs::Multisig(m) => &mut m.exprs,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackExpr {
    pos: u32,
    //data: ExprData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BytesExpr(Box<[u8]>);

impl Deref for BytesExpr {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExprData {
    uses: Vec<ExprUsage>,
    // TODO lenghts, values
}

/*
impl ExprData {
    pub fn new() -> Self {
        Self { uses: Vec::new() }
    }
}*/

// TODO do something with this
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExprUsage {
    //Pubkey,
    //Preimage,
    //Signature,
}

impl fmt::Display for OpExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn write_args(f: &mut fmt::Formatter<'_>, args: &[Expr]) -> fmt::Result {
            let mut first = true;

            for e in args {
                if !first {
                    write!(f, ", ")?;
                }
                first = false;
                write!(f, "{e}")?;
            }

            Ok(())
        }

        write!(f, "{}(", self.opcode())?;

        if let OpExprArgs::Multisig(args) = &self.args {
            write!(f, "sigs=[")?;
            write_args(f, args.sigs())?;
            write!(f, "], pubkeys=[")?;
            write_args(f, args.keys())?;
            write!(f, "]")?;
        } else {
            write_args(f, self.args())?;
        }

        write!(f, ")")
    }
}

impl fmt::Display for StackExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<stack item #{}>", self.pos)
    }
}

impl fmt::Display for BytesExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<")?;
        for byte in &**self {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ">")
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
            (Self::Op(a), Self::Op(b)) => {
                // smallest opcode first
                match a.opcode().cmp(&b.opcode()) {
                    Ordering::Equal => {}
                    ord => return ord,
                }

                // TODO opcodes are equal, so amount of args is equal, except for checkmultisig, check this
                match a.args().len().cmp(&b.args().len()) {
                    Ordering::Equal => {}
                    ord => return ord,
                }

                for i in 0..a.args().len() {
                    match a.args()[i].cmp(&b.args()[i]) {
                        Ordering::Equal => {}
                        ord => return ord,
                    }
                }

                Ordering::Equal
            }
            (Self::Stack(a), Self::Stack(b)) => a.pos.cmp(&b.pos),
            (Self::Bytes(a), Self::Bytes(b)) => a.cmp(b),
            (a, b) => b.priority().cmp(&a.priority()),
        }
    }
}

impl Expr {
    pub fn priority(&self) -> u8 {
        match self {
            Expr::Bytes(_) => 0,
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
        Self::Stack(StackExpr { pos: u32::MAX })
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
                                    *self = Expr::bytes_owned(encode_int(b.len() as i64));
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
                                let hash: Box<[u8]> = match op {
                                    Opcode1::OP_RIPEMD160 | Opcode1::OP_SHA1 => {
                                        let hash = match op {
                                            Opcode1::OP_RIPEMD160 => {
                                                ripemd160::Hash::hash(b).to_byte_array()
                                            }
                                            Opcode1::OP_SHA1 => sha1::Hash::hash(b).to_byte_array(),
                                            _ => unreachable!(),
                                        };
                                        Box::new(hash)
                                    }
                                    Opcode1::OP_SHA256 => {
                                        let hash = sha256::Hash::hash(b).to_byte_array();
                                        Box::new(hash)
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
                                    *self = Expr::bytes(encode_bool(!decode_bool(arg)));
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
                                        *self = Opcode2::OP_EQUAL
                                            .expr(Box::new([args[0].clone(), Expr::bytes(FALSE)]));
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
                                *self = Expr::bytes_owned(encode_int(match op {
                                    Opcode2::OP_ADD => a + b,
                                    _ => a - b,
                                }));
                                return Ok(true);
                            }
                        }

                        Opcode2::OP_EQUAL => {
                            let [ref a1_, ref a2] = **args;
                            match (a1_, a2) {
                                (Expr::Bytes(a1), Expr::Bytes(a2)) => {
                                    *self = Expr::bytes(encode_bool(a1 == a2));
                                    return Ok(true);
                                }
                                (Expr::Op(a1), Expr::Bytes(a2)) => {
                                    if a1.opcode().returns_boolean() {
                                        if **a2 == *TRUE {
                                            *self = a1_.clone()
                                        } else if **a2 == *FALSE {
                                            *self = Opcode1::OP_NOT.expr(Box::new([a1_.clone()]))
                                        } else {
                                            *self = Expr::bytes(FALSE)
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
                                            *self = Expr::bytes(TRUE);
                                            Ok(true)
                                        };
                                    }
                                    if let Expr::Bytes(sig) = sig {
                                        if sig.len() == 0 {
                                            *self = Expr::bytes(FALSE);
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
                                        *self = Expr::bytes(FALSE);
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
                            .unwrap_or_else(|| Expr::bytes(TRUE));

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
