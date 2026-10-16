//! Readers and writers used by transaction serialization.
//!
//! With the `std` feature these are [`std::io`] types, so existing callers that
//! pass `std::io::Cursor` or any other `std::io::Read` / `std::io::Write` are
//! unchanged. Without `std`, a small alloc-only implementation covers the
//! `Cursor<Vec<u8>>`, `&[u8]`, and `Vec<u8>` shapes used by parse/serialize.

#[cfg(feature = "std")]
pub(crate) use std::io::{Cursor, Read, Result, Write};

#[cfg(not(feature = "std"))]
mod nostd {
    use alloc::vec::Vec;
    use core::fmt;

    /// I/O failure from the alloc-only reader/writer.
    ///
    /// Not part of the default (`std`) public API. `TransactionError::Io` stores
    /// a `std::io::Error` when `std` is enabled.
    #[derive(Debug, Clone, Copy)]
    pub struct Error {
        message: &'static str,
    }

    impl Error {
        pub(crate) fn new(message: &'static str) -> Self {
            Self { message }
        }
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.message)
        }
    }

    pub type Result<T> = core::result::Result<T, Error>;

    pub trait Read {
        fn read_exact(&mut self, buf: &mut [u8]) -> Result<()>;
    }

    pub trait Write {
        fn write_all(&mut self, buf: &[u8]) -> Result<()>;
    }

    pub struct Cursor<T> {
        inner: T,
        pos: usize,
    }

    impl<T> Cursor<T> {
        pub fn new(inner: T) -> Self {
            Self { inner, pos: 0 }
        }
    }

    impl<T: AsRef<[u8]>> Read for Cursor<T> {
        fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
            let data = self.inner.as_ref();
            let end = self
                .pos
                .checked_add(buf.len())
                .ok_or_else(|| Error::new("unexpected end of input"))?;
            if end > data.len() {
                return Err(Error::new("unexpected end of input"));
            }
            buf.copy_from_slice(&data[self.pos..end]);
            self.pos = end;
            Ok(())
        }
    }

    impl Write for Cursor<Vec<u8>> {
        fn write_all(&mut self, buf: &[u8]) -> Result<()> {
            let end = self.pos + buf.len();
            if end > self.inner.len() {
                self.inner.resize(end, 0);
            }
            self.inner[self.pos..end].copy_from_slice(buf);
            self.pos = end;
            Ok(())
        }
    }

    impl Write for Vec<u8> {
        fn write_all(&mut self, buf: &[u8]) -> Result<()> {
            self.extend_from_slice(buf);
            Ok(())
        }
    }

    impl Read for &[u8] {
        fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
            if buf.len() > self.len() {
                return Err(Error::new("unexpected end of input"));
            }
            let (head, tail) = self.split_at(buf.len());
            buf.copy_from_slice(head);
            *self = tail;
            Ok(())
        }
    }
}

#[cfg(not(feature = "std"))]
pub(crate) use nostd::{Cursor, Error, Read, Result, Write};
