use core::fmt;
use core::ops::{Deref, Index};
use core::slice::SliceIndex;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BytesExprBox(Box<[u8]>);

impl BytesExprBox {
    pub fn new(bytes: Box<[u8]>) -> Self {
        Self(bytes)
    }
}

impl Deref for BytesExprBox {
    type Target = BytesExpr;

    fn deref(&self) -> &Self::Target {
        BytesExpr::new(&self.0)
    }
}

impl AsRef<[u8]> for BytesExprBox {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<I: SliceIndex<[u8]>> Index<I> for BytesExprBox {
    type Output = I::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl fmt::Display for BytesExprBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.deref().fmt(f)
    }
}

#[repr(transparent)]
pub struct BytesExpr([u8]);

impl BytesExpr {
    pub fn new(bytes: &[u8]) -> &Self {
        unsafe { &*(bytes as *const [u8] as *const BytesExpr) }
    }

    pub fn new_mut(bytes: &mut [u8]) -> &mut Self {
        unsafe { &mut *(bytes as *mut [u8] as *mut BytesExpr) }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    // no clippy, this "is clearer and more explicit"
    #[allow(clippy::comparison_to_empty)]
    pub fn is_false(&self) -> bool {
        self.0 == []
    }

    pub fn is_true(&self) -> bool {
        self.0 == [1]
    }
}

impl AsRef<[u8]> for BytesExpr {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<I: SliceIndex<[u8]>> Index<I> for BytesExpr {
    type Output = I::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl fmt::Display for BytesExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ">")
    }
}
