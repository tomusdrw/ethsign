use memzero::Memzero;

/// A protected set of bytes.
pub struct Protected(pub Memzero<Vec<u8>>);

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
