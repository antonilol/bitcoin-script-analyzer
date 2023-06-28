use super::{Expr, OpExpr, OpExprArgs};
use crate::script_error::ScriptError;

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
