/// MIT License
///
/// Copyright (c) 2022 herrsmitty8128
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///  
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

pub mod error {

    use std::fmt::Display;

    /// An enumeration of the various error types used throughout *bc_hash*.
    #[derive(Debug, Clone)]
    pub enum Error {
        InvalidSliceLength,
        StringTooLong,
        StringTooShort,
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
                InvalidSliceLength => f.write_str("Slice is an invalid length"),
                StringTooLong => f.write_str("String has too many characters"),
                StringTooShort => f.write_str("String has too few characters"),
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
}

pub mod crypto {

    use std::fmt::Display;
    use std::fs::File;
    use std::path::Path;

    pub trait Digest<'a>:
        Default
        + Display
        + PartialEq
        + Eq
        + TryFrom<&'a str>
        + TryFrom<&'a File>
        + TryFrom<&'a Path>
        + From<&'a [u8]>
        + From<&'a mut Vec<u8>>
    {
        const DIGEST_SIZE: usize;
        fn reset(&mut self);
        fn as_bytes(&self) -> &[u8];
        fn as_bytes_mut(&mut self) -> &[u8];
        fn deserialize_from(&mut self, bytes: &[u8]) -> crate::error::Result<()>;
        fn deserialize(bytes: &[u8]) -> crate::error::Result<Self>;
        fn serialize_to(&self, bytes: &mut [u8]) -> crate::error::Result<()>;
        fn calculate(digest: &mut Self, buf: &mut Vec<u8>);
    }
}

pub mod sha256 {

    use crate::crypto::Digest as CryptoDigest;
    use crate::error::{Error, Result};
    use std::cmp::Ordering;
    use std::fmt::Display;
    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::path::Path;

    /// An array of 64 constants consisting of the first 32 bits of the fractional parts of the cube roots of the first 64 primes 2 through 311.
    pub const CONSTANTS: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    /// An array used to initialize a digest to the first 32 bits of the fractional parts of the square roots of the first 8 primes, 2 through 19.
    pub const INITIAL_VALUES: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    /// Represents the message schedule buffer used in the processing of the SHA-256 algorithm.
    struct MsgSch {
        w: [u32; 64],
    }

    impl Default for MsgSch {
        /// Creates a new MsgSch object initialized with zeros.
        fn default() -> Self {
            Self { w: [0; 64] }
        }
    }

    impl MsgSch {
        // Copies 64 bytes (512-bits) from *chunk* into the first 16 words of the message schedule. Panics if chunk.len() != 64.
        fn load(&mut self, chunk: &[u8]) {
            let mut temp: [u8; 4] = [0; 4];
            for (i, offset) in (0..64).step_by(4).enumerate() {
                temp.clone_from_slice(&chunk[offset..(offset + 4)]);
                self.w[i] = u32::from_be_bytes(temp);
            }
            self.w[16..64].fill(0);
        }
    }

    #[derive(Debug, Clone)]
    /// Represents a SHA-256 digest in binary format.
    pub struct Digest {
        data: [u32; 8],
    }

    /// The total size of a digest object's data array in bytes.
    //pub const DIGEST_SIZE: usize = 32;

    impl Eq for Digest {}

    impl PartialEq for Digest {
        /// Returns true if self and other contain the same values in their data arrays. Otherwise, it returns false.
        fn eq(&self, other: &Self) -> bool {
            for i in 0..8 {
                if self.data[i] != other.data[i] {
                    return false;
                }
            }
            true
        }

        /// Returns true if self and other do not contain the same values in their data arrays. Otherwise, it returns true.
        #[allow(clippy::partialeq_ne_impl)]
        fn ne(&self, other: &Self) -> bool {
            !self.eq(other)
        }
    }

    impl Default for Digest {
        /// Creates and returns a new digest object by calling Digest::new().
        fn default() -> Self {
            Self {
                data: INITIAL_VALUES,
            }
        }
    }

    impl Display for Digest {
        /// Implementation of the Display trait for sha256::Digest.
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut data: String = String::new();
            for n in self.data {
                data.push_str(&format!("{:08x}", n));
            }
            f.write_str(&data)
        }
    }

    impl TryFrom<&Path> for Digest {
        type Error = std::io::Error;
        /// Calculates and returns a new SHA-256 digest from the contents of the file located at *path*.
        /// Ok(Digest) is returned on success. Err(io::Error) is returned on failure.
        /// The *path* argument must contain the path and file name of the file for which the digest should be calculated.
        fn try_from(path: &Path) -> std::result::Result<Self, Self::Error> {
            Self::try_from(&File::open(path)?)
        }
    }

    impl TryFrom<&File> for Digest {
        type Error = std::io::Error;
        /// Calculates and returns a new SHA-256 digest from the contents of *file*.
        /// Returns Ok(Digest) on success or Err(io::Error) on failure.
        fn try_from(file: &File) -> std::result::Result<Self, Self::Error> {
            const BUF_SIZE: usize = 2048;
            let len: usize = file.metadata()?.len() as usize;
            let mut digest: Digest = Digest::default();
            let mut msg_sch: MsgSch = MsgSch::default();
            let mut reader: BufReader<&File> = BufReader::new(file);
            let mut buf: [u8; BUF_SIZE] = [0; BUF_SIZE];
            let mut cum_read: usize = 0;
            let mut bytes_read: usize = 0;
            loop {
                bytes_read += reader.read(&mut buf[bytes_read..(BUF_SIZE - bytes_read)])?;
                cum_read += bytes_read;
                if cum_read >= len {
                    Self::chunk_loop(
                        &mut Vec::from(&buf[0..bytes_read]),
                        &mut msg_sch,
                        &mut digest,
                        len,
                    );
                    return Ok(digest);
                }
                if bytes_read >= 64 {
                    let r: usize = bytes_read % 64;
                    let n: usize = bytes_read - r;
                    for i in (0..n).step_by(64) {
                        msg_sch.load(&buf[i..(i + 64)]);
                        digest.update(&mut msg_sch);
                    }
                    buf.copy_within(n..bytes_read, 0);
                    bytes_read = r;
                }
            }
        }
    }

    impl TryFrom<&str> for Digest {
        type Error = Error;
        /// Attempts to create a new sha-256 digest from a string. The string must be 64 characters
        /// in hexidecimal format and may include the "0x" prefix. Ok(Digest) is returned on success. Err(String)
        /// is returned on failure.
        fn try_from(string: &str) -> std::result::Result<Self, Self::Error> {
            let s: String = string.to_ascii_lowercase();
            let mut src: &str = s.trim();
            if let Some(s) = src.strip_prefix("0x") {
                src = s
            }
            match src.len().cmp(&64) {
                Ordering::Greater => Err(Error::StringTooLong),
                Ordering::Less => Err(Error::StringTooShort),
                Ordering::Equal => {
                    let mut digest = Digest::default();
                    for (i, offset) in (0..64).step_by(8).enumerate() {
                        digest.data[i] = u32::from_str_radix(&src[offset..(offset + 8)], 16)?
                    }
                    Ok(digest)
                }
            }
        }
    }

    impl From<&[u8]> for Digest {
        /// Calculates and returns a new SHA-256 digest from a slice of bytes.
        fn from(bytes: &[u8]) -> Self {
            Self::from(Vec::from(bytes).as_mut())
        }
    }

    impl From<&mut Vec<u8>> for Digest {
        /// Calculates and returns a new SHA-256 digest from a vector of bytes.
        fn from(buf: &mut Vec<u8>) -> Self {
            let mut digest: Digest = Digest::default();
            Self::calculate(&mut digest, buf);
            digest
        }
    }

    impl<'a> CryptoDigest<'a> for Digest {
        /// The size of a digest in bytes.
        const DIGEST_SIZE: usize = 32;

        /// Resets the digest's data buffer to the first 32 bits of the fractional parts of the square roots of the first 8 primes, 2 through 19.
        fn reset(&mut self) {
            self.data = INITIAL_VALUES;
        }

        /// Returns self's underlying array as a slice of bytes.
        fn as_bytes(&self) -> &[u8] {
            unsafe {
                std::slice::from_raw_parts(self.data[..].as_ptr() as *const u8, Self::DIGEST_SIZE)
            }
        }

        /// Returns self's underlying array as a mutable slice of bytes.
        fn as_bytes_mut(&mut self) -> &[u8] {
            unsafe {
                std::slice::from_raw_parts_mut(
                    self.data[..].as_mut_ptr() as *mut u8,
                    Self::DIGEST_SIZE,
                )
            }
        }

        /// Attempts to transmute a slice of bytes into an existing sha256::Digest object using little endian byte order.
        /// Returns Ok<()> on success or Err<sha256::Error> on failure.
        /// Returns Err(Error::InvalidSliceLength) if the length of the slice is not equal to 32 bytes.
        fn deserialize_from(&mut self, bytes: &[u8]) -> Result<()> {
            if bytes.len() != 32 {
                Err(Error::InvalidSliceLength)
            } else {
                let mut temp: [u8; 4] = [0; 4];
                for (i, offset) in (0..32).step_by(4).enumerate() {
                    temp.clone_from_slice(&bytes[offset..(offset + 4)]);
                    self.data[i] = u32::from_le_bytes(temp);
                }
                Ok(())
            }
        }

        /// Attempts to transmute a slice of bytes into a new sha256::Digest object using little endian byte order.
        /// Returns Ok<Digest> on success or Err<sha256::Error> on failure.
        /// Returns Err(Error::InvalidSliceLength) if the length of the slice is not equal to 32 bytes.
        fn deserialize(bytes: &[u8]) -> Result<Self> {
            let mut digest = Digest::default();
            digest.deserialize_from(bytes)?;
            Ok(digest)
        }

        /// Attempts to serialize self to a slice of bytes using little endian byte order.
        /// Returns Ok<()> on success or Err<sha256::Error> on failure.
        /// Returns Err(Error::InvalidSliceLength) if the length of the slice is not equal to 32 bytes.
        fn serialize_to(&self, bytes: &mut [u8]) -> Result<()> {
            if bytes.len() != 32 {
                Err(Error::InvalidSliceLength)
            } else {
                for (i, offset) in (0..32).step_by(4).enumerate() {
                    bytes[offset..(offset + 4)].clone_from_slice(&self.data[i].to_le_bytes());
                }
                Ok(())
            }
        }

        /// Calculates the SHA-256 digest from a vector of bytes and writes it to the digest.
        fn calculate(digest: &mut Digest, buf: &mut Vec<u8>) {
            digest.reset();
            let len: usize = buf.len();
            let mut msg_sch: MsgSch = MsgSch::default();
            Self::chunk_loop(buf, &mut msg_sch, digest, len);
            buf.truncate(len);
        }
    }

    impl Digest {
        /// This is a private function used in the calculation of SHA-256, which Performs the following actions:
        /// 1.) Appends a single "1" to the buffer.
        /// 2.) Rounds the buffer to nearest multiple of 512 bits while leaving room for 8 more bytes.
        /// 3.) Converts the bit count of the buffer into an 8-byte array in big endian format and appends it to the buffer.
        /// 4.) Breaks the vector into 512-bit slices used to load the message schedule and update the digest.
        /// This is known as the "chunk loop".
        fn chunk_loop(buf: &mut Vec<u8>, msg_sch: &mut MsgSch, digest: &mut Digest, len: usize) {
            buf.push(128u8);
            while (buf.len() + 8) % 64 != 0 {
                buf.push(0u8);
            }
            buf.extend_from_slice(&((len * 8) as u64).to_be_bytes());
            for i in (0..buf.len()).step_by(64) {
                msg_sch.load(&buf[i..(i + 64)]);
                digest.update(msg_sch);
            }
        }

        /// This is a private function used in the calculation of SHA-256, which updates the value of the digest based on the contents of the message schedule.
        fn update(&mut self, msg_sch: &mut MsgSch) {
            // extend the first 16 words into the remaining 48 words of the message schedule
            for i in 0..48 {
                let w0: u32 = msg_sch.w[i];
                let mut w1: u32 = msg_sch.w[i + 1];
                w1 = w1.rotate_right(7) ^ w1.rotate_right(18) ^ (w1 >> 3);
                let w9: u32 = msg_sch.w[i + 9];
                let mut w14: u32 = msg_sch.w[i + 14];
                w14 = w14.rotate_right(17) ^ w14.rotate_right(19) ^ (w14 >> 10);
                msg_sch.w[i + 16] = w0.wrapping_add(w1.wrapping_add(w9.wrapping_add(w14)));
            }

            // set the working variables to the hash values
            let mut a: u32 = self.data[0];
            let mut b: u32 = self.data[1];
            let mut c: u32 = self.data[2];
            let mut d: u32 = self.data[3];
            let mut e: u32 = self.data[4];
            let mut f: u32 = self.data[5];
            let mut g: u32 = self.data[6];
            let mut h: u32 = self.data[7];

            // the "compression loop"
            for (i, constant) in CONSTANTS.iter().enumerate() {
                let sigma0: u32 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let sigma1: u32 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let choice: u32 = (e & f) ^ ((e ^ u32::MAX) & g);
                let majority: u32 = (a & b) ^ (a & c) ^ (b & c);
                let temp1: u32 = h.wrapping_add(
                    sigma1.wrapping_add(choice.wrapping_add(constant.wrapping_add(msg_sch.w[i]))),
                );
                let temp2: u32 = sigma0.wrapping_add(majority);
                // update working variables
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            // add the working variables to the digest
            self.data[0] = self.data[0].wrapping_add(a);
            self.data[1] = self.data[1].wrapping_add(b);
            self.data[2] = self.data[2].wrapping_add(c);
            self.data[3] = self.data[3].wrapping_add(d);
            self.data[4] = self.data[4].wrapping_add(e);
            self.data[5] = self.data[5].wrapping_add(f);
            self.data[6] = self.data[6].wrapping_add(g);
            self.data[7] = self.data[7].wrapping_add(h);
        }
    }
}
