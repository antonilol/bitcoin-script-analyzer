use super::{Expr, Opcode1, Opcode2, Opcode3};
use crate::opcode::{Opcode, opcodes};
use crate::script_error::ScriptError;

use core::cmp::Ordering;
use core::fmt;

use alloc::boxed::Box;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpExpr {
    pub args: OpExprArgs,
    error: Option<ScriptError>,
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

impl PartialOrd for OpExpr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OpExpr {
    fn cmp(&self, other: &Self) -> Ordering {
        // smallest opcode first
        match self.opcode().cmp(&other.opcode()) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // TODO opcodes are equal, so amount of args is equal, except for checkmultisig, check this
        match self.args().len().cmp(&other.args().len()) {
            Ordering::Equal => {}
            ord => return ord,
        }

        for i in 0..self.args().len() {
            match self.args()[i].cmp(&other.args()[i]) {
                Ordering::Equal => {}
                ord => return ord,
            }
        }

        Ordering::Equal
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpExprArgs {
    Args1(Opcode1, Box<[Expr; 1]>),
    Args2(Opcode2, Box<[Expr; 2]>),
    Args3(Opcode3, Box<[Expr; 3]>),
    Multisig(MultisigArgs),
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
