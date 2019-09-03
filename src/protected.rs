use zeroize::Zeroize;

/// A protected set of bytes.
#[derive(Clone)]
pub struct Protected(Vec<u8>);

impl<T: Into<Vec<u8>>> From<T> for Protected {
    fn from(x: T) -> Self {
        Protected::new(x)
    }
}

impl AsRef<[u8]> for Protected {
    fn as_ref(&self) -> &[u8] {
        &*self.0
    }
}

impl Protected {
    /// Create new protected set of bytes.
    pub fn new<T: Into<Vec<u8>>>(m: T) -> Self {
        Protected(m.into())
    }
}

impl Drop for Protected {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Protected {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        let len = self.0.len();
        if len > 2 {
            write!(fmt, "Protected({}..{})", self.0[0], self.0[len - 1])
        } else {
            write!(fmt, "Protected")
        }
    }
}
