// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

use std::fmt::Display;

/// An enumeration of the various error types used throughout ```bc_hash```.
#[derive(Debug, Clone)]
pub enum Error {
    BadStreamPosition(u64),
    BlockNumDoesNotExist,
    BlockSizeTooBig,
    FileIsEmpty,
    IntegerOverflow,
    InvalidBlockHash(u64),
    InvalidBlockSize(u64),
    InvalidDataLength(usize),
    InvalidDigestLength(usize),
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
            BadStreamPosition(n) => f.write_fmt(format_args!("Current stream position {} is not an even multiple of the block size.", n)),
            BlockNumDoesNotExist => f.write_str("Block number too large (out of bounds) and does not exist."),
            BlockSizeTooBig => f.write_str("Block size is greater than u32::MAX - DIGEST_SIZE"),
            FileIsEmpty => f.write_str("File is empty."),
            IntegerOverflow => {
                f.write_str("Integer overflowed when calculating file position.")
            }
            InvalidBlockHash(n) => f.write_fmt(format_args!("The previous block hash saved in block number {} is not the same as the previous block's hash", n)),
            InvalidBlockSize(n) => f.write_fmt(format_args!("Block size {} is not valid", n)),
            InvalidDataLength(n) => {
                f.write_fmt(format_args!("Data length {} is not valid", n))
            }
            InvalidDigestLength(n) => {
                f.write_fmt(format_args!("Digest length {} is not valid", n))
            }
            InvalidFileSize => f.write_str("File size is not a multiple of block size."),
            InvalidIndex => f.write_str("Invalid index (out of range)."),
            InvalidMerkleLeaves => f.write_str("Invalid merkle tree leaves"),
            InvalidSliceLength => f.write_str("Slice has an invalid length"),
            IOError(e) => f.write_fmt(format_args!("{}", e)),
            //IOError(e) => f.write_str(e.to_string().as_str()),
            ParseError(e) => f.write_fmt(format_args!("{}", e)),
            PathDoesNotExist => f.write_str("The file path does not exist."),
            PathIsNotAFile => f.write_str("The file path is not a file."),
            SliceTooLong => f.write_str("Slice is too long."),
            SliceTooShort => f.write_str("Slice has too few bytes."),
            StringTooLong => f.write_str("String has too many characters"),
            StringTooShort => f.write_str("String has too few characters"),
            ZeroBlockSize => f.write_str("Block size can not be zero."),
        }
    }
}

/// Implementation of the standard Error trait for sha256::Error
impl std::error::Error for Error {}

/// A type used to standardize the result type used throughout bc_hash. This simplifies the Result<> return
/// types throughout the library and helps ensure the consistent use of Self::Error, which can be easily
/// used with other error types in the standard library.
pub type Result<T> = std::result::Result<T, Error>;
