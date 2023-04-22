use std::fmt::Display;

/// An enumeration of the various error types used throughout ```bc_hash```.
#[derive(Debug, Clone)]
pub enum Error {
    InvalidDigestLength(usize),
    InvalidSliceLength,
    StringTooLong,
    StringTooShort,
    InvalidMerkleLeaves,
    InvalidIndex,
    SliceTooLong,
    SliceTooShort,
    ParseError(std::num::ParseIntError),
    IOError(std::io::ErrorKind),
}

impl From<std::num::ParseIntError> for Error {
    /// Converts from a std::num::ParseIntError to a sha256::Error.
    fn from(e: std::num::ParseIntError) -> Self {
        Error::ParseError(e)
    }
}

impl From<std::io::Error> for Error {
    /// Converts from a std::io::Error to a sha256::Error.
    fn from(e: std::io::Error) -> Self {
        Error::IOError(e.kind())
    }
}

impl Display for Error {
    /// Implementation of the Display trait for sha256::Error.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            InvalidDigestLength(n) => {
                f.write_fmt(format_args!("Digest length is not equal to {}", n))
            }
            InvalidSliceLength => f.write_str("Slice is an invalid length"),
            StringTooLong => f.write_str("String has too many characters"),
            StringTooShort => f.write_str("String has too few characters"),
            InvalidMerkleLeaves => f.write_str("Invalid merkle tree leaves"),
            InvalidIndex => f.write_str("Invalid index (out of range)."),
            SliceTooLong => f.write_str("Slice is too long."),
            SliceTooShort => f.write_str("Slice has too few bytes."),
            ParseError(e) => f.write_fmt(format_args!("{}", e)),
            IOError(e) => f.write_fmt(format_args!("{}", e)),
        }
    }
}

/// Implementation of the standard Error trait for sha256::Error
impl std::error::Error for Error {}

/// A type used to standardize the result type used throughout bc_hash. This simplifies the Result<> return
/// types throughout the library and helps ensure the consistent use of Self::Error, which can be easily
/// used with other error types in the standard library.
pub type Result<T> = std::result::Result<T, Error>;
