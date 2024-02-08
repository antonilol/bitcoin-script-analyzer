use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StackExpr(u32);

impl StackExpr {
    pub fn new(pos: u32) -> Self {
        Self(pos)
    }
}

impl fmt::Display for StackExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<stack item #{}>", self.0)
    }
}
