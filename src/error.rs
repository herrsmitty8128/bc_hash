// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

use std::fmt::Display;

/// An enumeration of the various error types used throughout ```bc_hash```.
#[derive(Debug, Clone)]
pub enum ErrorKind {
    BadStreamPosition,
    BlockNumDoesNotExist,
    BlockSizeTooBig,
    FileIsEmpty,
    IntegerOverflow,
    InvalidBlockHash,
    InvalidBlockSize,
    InvalidDataLength,
    InvalidDigestLength,
    InvalidFileSize,
    InvalidIndex,
    InvalidMerkleLeaves,
    InvalidSliceLength,
    IOError(std::io::ErrorKind),
    ParseError(std::num::ParseIntError),
    PathDoesNotExist,
    PathIsNotAFile,
    SliceTooLong,
    SliceTooShort,
    StringTooLong,
    StringTooShort,
    ZeroBlockSize,
}

impl Display for ErrorKind {
    /// Implementation of the Display trait for sha256::Error.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ErrorKind::*;
        match self {
            BadStreamPosition => f.write_str("Bad stream position."),
            BlockNumDoesNotExist => f.write_str("Block number does not exist (out of bounds)."),
            BlockSizeTooBig => f.write_str("Block size is to big."),
            FileIsEmpty => f.write_str("File is empty."),
            IntegerOverflow => f.write_str("Integer overflow."),
            InvalidBlockHash => f.write_str("Invalid block hash."),
            InvalidBlockSize => f.write_str("Invalid block size."),
            InvalidDataLength =>  f.write_str("Invalid data length."),
            InvalidDigestLength => f.write_str("Invalid digest length."),
            InvalidFileSize => f.write_str("Invalid file size."),
            InvalidIndex => f.write_str("Invalid index (out of bounds)."),
            InvalidMerkleLeaves => f.write_str("Invalid merkle tree leaves."),
            InvalidSliceLength => f.write_str("Invalid slice length."),
            IOError(e) => f.write_str(&e.to_string()),
            ParseError(e) => f.write_str(&e.to_string()),
            PathDoesNotExist => f.write_str("Path does not exist."),
            PathIsNotAFile => f.write_str("Path is not a file."),
            SliceTooLong => f.write_str("Slice too long."),
            SliceTooShort => f.write_str("Slice too short."),
            StringTooLong => f.write_str("String too long."),
            StringTooShort => f.write_str("String to short."),
            ZeroBlockSize => f.write_str("Zero block size."),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorKind,
    message: &'static str,
}

impl Error {
    pub fn new(kind: ErrorKind, message: &'static str) -> Self {
        Self { kind, message }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{} {}", self.kind, self.message))
    }
}

impl From<std::num::ParseIntError> for Error {
    /// Converts from a std::num::ParseIntError to a sha256::Error.
    fn from(e: std::num::ParseIntError) -> Self {
        Error::new(ErrorKind::ParseError(e), "Parse integer error.")
    }
}

impl From<std::io::Error> for Error {
    /// Converts from a std::io::Error to a sha256::Error.
    fn from(e: std::io::Error) -> Self {
        Error::new(ErrorKind::IOError(e.kind()), "IO error.")
    }
}

/// Implementation of the standard Error trait for sha256::Error
impl std::error::Error for Error {}

/// A type used to standardize the result type used throughout bc_hash. This simplifies the Result<> return
/// types throughout the library and helps ensure the consistent use of Self::Error, which can be easily
/// used with other error types in the standard library.
pub type Result<T> = std::result::Result<T, Error>;
