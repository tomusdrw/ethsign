/// A protected set of bytes.
pub struct Protected(pub Vec<u8>);

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

impl Drop for Protected {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
    }
}
