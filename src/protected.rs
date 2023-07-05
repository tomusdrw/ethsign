use zeroize::Zeroize;

/// A protected set of bytes.
#[derive(Clone)]
pub struct Unprotected(Vec<u8>);

impl<T: Into<Vec<u8>>> From<T> for Unprotected {
    fn from(x: T) -> Self {
        Unprotected::new(x)
    }
}

impl AsRef<[u8]> for Unprotected {
    fn as_ref(&self) -> &[u8] {
        &*self.0
    }
}

impl Unprotected {
    /// Create new unprotected set of bytes.
    pub fn new<T: Into<Vec<u8>>>(m: T) -> Self {
        Unprotected(m.into())
    }
}

impl Drop for Unprotected {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Unprotected {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        let len = self.0.len();
        if len > 2 {
            write!(fmt, "Unprotected({}..{})", self.0[0], self.0[len - 1])
        } else {
            write!(fmt, "Unprotected")
        }
    }
}
