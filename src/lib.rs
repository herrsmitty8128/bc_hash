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
use std::cmp::Ordering;
use std::fmt::Display;
use std::str::FromStr;

pub mod error {

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
}

#[derive(Debug, Clone)]
pub struct Digest<const S: usize>(pub [u8; S]);

impl<const S: usize> Default for Digest<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const S: usize> PartialEq for Digest<S> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<const S: usize> Display for Digest<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut data: String = String::new();
        for n in self.0 {
            data.push_str(&format!("{:02x}", n));
        }
        f.write_str(&data)
    }
}

impl<const S: usize> FromStr for Digest<S> {
    type Err = crate::error::Error;
    /// Attempts to create a new sha-256 digest from a string. The string must be 64 characters
    /// in hexidecimal format and may include the "0x" prefix. Ok(Digest) is returned on success.
    ///  Err(String) is returned on failure.
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let s: String = string.to_ascii_lowercase();
        let mut src: &str = s.trim();
        if let Some(s) = src.strip_prefix("0x") {
            src = s
        }
        match src.len().cmp(&(S * 2)) {
            Ordering::Greater => Err(crate::error::Error::StringTooLong),
            Ordering::Less => Err(crate::error::Error::StringTooShort),
            Ordering::Equal => {
                let mut digest: Digest<S> = Digest::new();
                for (i, offset) in (0..(S * 2)).step_by(2).enumerate() {
                    digest.0[i] = u8::from_str_radix(&src[offset..(offset + 2)], 16)?
                }
                Ok(digest)
            }
        }
    }
}

#[allow(clippy::len_without_is_empty)]
impl<const S: usize> Digest<S> {
    pub fn new() -> Self {
        Digest([0; S])
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn from_bytes(bytes: &mut [u8]) -> std::result::Result<Digest<S>, crate::error::Error> {
        match bytes.len().cmp(&S) {
            Ordering::Greater => Err(crate::error::Error::SliceTooLong),
            Ordering::Less => Err(crate::error::Error::SliceTooShort),
            Ordering::Equal => {
                let mut digest: Digest<S> = Digest::new();
                digest.0.clone_from_slice(bytes);
                Ok(digest)
            }
        }
    }
}

pub mod merkle {

    use crate::error;
    use crate::OneWayHash;

    /// Calculates the merkle root for a vector of leaves where each leaf is the hash digest of
    /// a record in a block of data. This function reduces the ```leaves``` argument down to a
    /// single element in the vector, which is the root. It returns a ```bool``` value indicating
    /// whether or not a mutation was encountered during the calculation.
    pub fn compute_root<const MDLEN: usize, H: OneWayHash>(
        leaves: &mut Vec<[u8; MDLEN]>,
        hasher: &mut H,
    ) -> error::Result<bool> {
        let mut mutation: bool = false;
        while leaves.len() > 1 {
            for i in 0..leaves.len() - 1 {
                // search for a mutation and set the mutation variable to true if we find one
                if leaves[i] == leaves[i + 1] {
                    mutation = true;
                }
            }
            if leaves.len() & 1 != 0 {
                // the vector contains an odd number of leaves, so copy and append the last leaf to make it an even number.
                match leaves.last() {
                    Some(d) => leaves.push(*d),
                    None => return Err(error::Error::InvalidMerkleLeaves), // should never get here
                }
            }
            for (i, j) in (0..leaves.len()).step_by(2).enumerate() {
                hasher
                    .update(unsafe { std::slice::from_raw_parts(leaves[j].as_ptr(), 2 * MDLEN) })
                    .finish(&mut leaves[i])?;
            }
            leaves.truncate(leaves.len() / 2)
        }
        Ok(mutation)
    }

    pub enum ChildNode<const MDLEN: usize> {
        Left([u8; MDLEN]),
        Right([u8; MDLEN]),
    }

    pub type Proof<const MDLEN: usize> = Vec<ChildNode<MDLEN>>;

    pub fn compute_proof<const MDLEN: usize, H: OneWayHash>(
        leaves: &mut Vec<[u8; MDLEN]>,
        mut index: usize,
        hasher: &mut H,
    ) -> error::Result<(Proof<MDLEN>, bool)> {
        let mut mutation: bool = false;
        let mut proof: Proof<MDLEN> = Proof::new();
        if index >= leaves.len() {
            Err(error::Error::InvalidIndex)
        } else {
            while leaves.len() > 1 {
                for i in 0..leaves.len() - 1 {
                    if leaves[i] == leaves[i + 1] {
                        mutation = true;
                    }
                }
                if leaves.len() & 1 != 0 {
                    match leaves.last() {
                        Some(d) => leaves.push(*d),
                        None => return Err(error::Error::InvalidMerkleLeaves),
                    }
                }
                proof.push(if index & 1 == 1 {
                    ChildNode::Left(leaves[index ^ 1])
                } else {
                    ChildNode::Right(leaves[index ^ 1])
                });
                for (i, j) in (0..leaves.len()).step_by(2).enumerate() {
                    hasher
                        .update(unsafe {
                            std::slice::from_raw_parts(leaves[j].as_ptr(), 2 * MDLEN)
                        })
                        .finish(&mut leaves[i])?;
                }
                leaves.truncate(leaves.len() / 2);
                index >>= 2;
            }
            Ok((proof, mutation))
        }
    }

    pub fn prove<H: OneWayHash, const MDLEN: usize>(
        merkle_proof: Proof<MDLEN>,
        data_hash: &mut [u8; MDLEN],
    ) -> error::Result<[u8; MDLEN]> {
        let mut data: [[u8; MDLEN]; 2] = [[0; MDLEN]; 2];
        let mut digest: [u8; MDLEN] = *data_hash;
        let mut hasher: H = H::init();
        for child in merkle_proof.iter() {
            match child {
                ChildNode::Left(sibling) => {
                    data[0] = *sibling;
                    data[1] = digest;
                }
                ChildNode::Right(sibling) => {
                    data[0] = digest;
                    data[1] = *sibling;
                }
            }
            hasher
                .update(unsafe { std::slice::from_raw_parts(data[0].as_ptr(), 2 * MDLEN) })
                .finish(&mut digest)?;
        }
        Ok(digest)
    }
}

pub trait OneWayHash
where
    Self: Sized,
{
    fn init() -> Self;
    fn reset(&mut self);
    fn update(&mut self, data: &[u8]) -> &mut Self;
    fn finish(&mut self, digest: &mut [u8]) -> error::Result<()>;
}

pub mod sha3 {

    use std::marker::PhantomData;

    const KECCAKF_RNDC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];

    const KECCAKF_ROTC: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];

    const KECCAKF_PILN: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    union State {
        b: [u8; 200], // 8-bit bytes
        q: [u64; 25], // 64-bit words
    }

    // state context
    pub struct Context<const B: usize> {
        st: State,
        pt: usize,
        rsiz: usize,
        _s: PhantomData<usize>,
    }

    impl<const B: usize> Context<B> {
        fn init() -> Context<B> {
            Self {
                st: State { q: [0; 25] },
                pt: 0,
                rsiz: 200 - (2 * B),
                _s: PhantomData,
            }
        }

        /// update state with more data
        fn update(&mut self, data: &[u8]) -> &mut Self {
            unsafe {
                let mut j: usize = self.pt;
                for byte in data {
                    self.st.b[j] ^= byte;
                    j += 1;
                    if j >= self.rsiz {
                        self.keccakf();
                        j = 0;
                    }
                }
                self.pt = j;
                self
            }
        }

        /// finalize and output a hash
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            if digest.len() != B {
                Err(crate::error::Error::InvalidDigestLength(B))
            } else {
                unsafe {
                    self.st.b[self.pt] ^= 0x06;
                    self.st.b[self.rsiz - 1] ^= 0x80;
                    self.keccakf();
                    digest.copy_from_slice(&self.st.b[..B]);
                }
                Ok(())
            }
        }

        fn shake_xof(&mut self) {
            unsafe {
                self.st.b[self.pt] ^= 0x1F;
                self.st.b[self.rsiz - 1] ^= 0x80;
                self.keccakf();
                self.pt = 0;
            }
        }

        fn shake_out(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            if digest.is_empty() {
                Err(crate::error::Error::InvalidDigestLength(0))
            } else {
                unsafe {
                    let mut j = self.pt;
                    for byte in digest {
                        if j >= self.rsiz {
                            self.keccakf();
                            j = 0;
                        }
                        *byte = self.st.b[j];
                        j += 1;
                    }
                    self.pt = j;
                }
                Ok(())
            }
        }

        /// Compression function.
        unsafe fn keccakf(&mut self) {
            // endianess conversion. this is redundant on little-endian targets
            #[cfg(target_endian = "big")]
            for i in 0..25 {
                self.st.q[i] = self.st.q[i].to_le();
            }

            // actual iteration
            for r in KECCAKF_RNDC {
                let mut bc: [u64; 5] = [0; 5];

                // Theta
                for (i, item) in bc.iter_mut().enumerate() {
                    *item = self.st.q[i]
                        ^ self.st.q[i + 5]
                        ^ self.st.q[i + 10]
                        ^ self.st.q[i + 15]
                        ^ self.st.q[i + 20];
                }

                for i in 0..5 {
                    let t: u64 = bc[(i + 4) % 5] ^ (bc[(i + 1) % 5]).rotate_left(1);
                    for j in (0..25).step_by(5) {
                        self.st.q[j + i] ^= t;
                    }
                }

                // Rho Pi
                let mut t: u64 = self.st.q[1];
                for i in 0..24 {
                    let j: usize = KECCAKF_PILN[i];
                    bc[0] = self.st.q[j];
                    self.st.q[j] = t.rotate_left(KECCAKF_ROTC[i]);
                    t = bc[0];
                }

                // Chi
                for j in (0..25).step_by(5) {
                    bc[..5].copy_from_slice(&self.st.q[j..(5 + j)]);
                    for i in 0..5 {
                        self.st.q[j + i] ^= (u64::MAX ^ bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                    }
                }

                // Iota
                self.st.q[0] ^= r;
            }

            // endianess conversion. this is redundant on little-endian targets
            #[cfg(target_endian = "big")]
            for i in 0..25 {
                self.st.q[i] = self.st.q[i].to_be();
            }
        }
    }

    pub type Sha3_224 = Context<28>;

    impl super::OneWayHash for Sha3_224 {
        #[inline]
        fn init() -> Sha3_224 {
            Context::<28>::init()
        }

        #[inline]
        fn reset(&mut self) {
            self.st = State { q: [0; 25] };
            self.pt = 0;
            self.rsiz = 200 - (2 * 28);
        }

        #[inline]
        fn update(&mut self, data: &[u8]) -> &mut Sha3_224 {
            self.update(data)
        }

        #[inline]
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            self.finish(digest)
        }
    }

    pub type Sha3_256 = Context<32>;

    impl super::OneWayHash for Sha3_256 {
        #[inline]
        fn init() -> Sha3_256 {
            Context::<32>::init()
        }

        #[inline]
        fn reset(&mut self) {
            self.st = State { q: [0; 25] };
            self.pt = 0;
            self.rsiz = 200 - (2 * 32);
        }

        #[inline]
        fn update(&mut self, data: &[u8]) -> &mut Sha3_256 {
            self.update(data)
        }

        #[inline]
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            self.finish(digest)
        }
    }

    pub type Sha3_384 = Context<48>;

    impl super::OneWayHash for Sha3_384 {
        #[inline]
        fn init() -> Sha3_384 {
            Context::<48>::init()
        }

        #[inline]
        fn reset(&mut self) {
            self.st = State { q: [0; 25] };
            self.pt = 0;
            self.rsiz = 200 - (2 * 48);
        }

        #[inline]
        fn update(&mut self, data: &[u8]) -> &mut Sha3_384 {
            self.update(data)
        }

        #[inline]
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            self.finish(digest)
        }
    }

    pub type Sha3_512 = Context<64>;

    impl super::OneWayHash for Sha3_512 {
        #[inline]
        fn init() -> Sha3_512 {
            Context::<64>::init()
        }

        #[inline]
        fn reset(&mut self) {
            self.st = State { q: [0; 25] };
            self.pt = 0;
            self.rsiz = 200 - (2 * 64);
        }

        #[inline]
        fn update(&mut self, data: &[u8]) -> &mut Sha3_512 {
            self.update(data)
        }

        #[inline]
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            self.finish(digest)
        }
    }

    pub struct Shake128 {
        ctx: Context<16>,
    }

    impl super::OneWayHash for Shake128 {
        #[inline]
        fn init() -> Shake128 {
            Shake128 {
                ctx: Context::<16>::init(),
            }
        }

        #[inline]
        fn reset(&mut self) {
            self.ctx.st = State { q: [0; 25] };
            self.ctx.pt = 0;
            self.ctx.rsiz = 200 - (2 * 16);
        }

        #[inline]
        fn update(&mut self, data: &[u8]) -> &mut Shake128 {
            self.ctx.update(data);
            self
        }

        #[inline]
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            self.ctx.shake_xof();
            self.ctx.shake_out(digest)
        }
    }

    pub struct Shake256 {
        ctx: Context<32>,
    }

    impl super::OneWayHash for Shake256 {
        #[inline]
        fn init() -> Shake256 {
            Shake256 {
                ctx: Context::<32>::init(),
            }
        }

        #[inline]
        fn reset(&mut self) {
            self.ctx.st = State { q: [0; 25] };
            self.ctx.pt = 0;
            self.ctx.rsiz = 200 - (2 * 32);
        }

        #[inline]
        fn update(&mut self, data: &[u8]) -> &mut Shake256 {
            self.ctx.update(data);
            self
        }

        #[inline]
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            self.ctx.shake_xof();
            self.ctx.shake_out(digest)
        }
    }
}

/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
/// https://en.wikipedia.org/wiki/SHA-2#Comparison_of_SHA_functions
/// https://en.wikipedia.org/wiki/Length_extension_attack
pub mod sha2 {

    use std::marker::PhantomData;

    /// An array of 64 constants consisting of the first 32 bits of the fractional parts of the cube roots of the first 64 primes 2 through 311.
    const CONSTANTS_256: [u32; 64] = [
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

    const CONSTANTS_512: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    /// An array used to initialize a digest to the first 32 bits of the fractional parts of the square roots of the first 8 primes, 2 through 19.
    const INITIAL_VALUES_224: [u32; 8] = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ];

    const INITIAL_VALUES_256: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    const INITIAL_VALUES_384: [u64; 8] = [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ];

    const INITIAL_VALUES_512: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    const INITIAL_VALUES_512_224: [u64; 8] = [
        0x8c3d37c819544da2,
        0x73e1996689dcd4d6,
        0x1dfab7ae32ff9c82,
        0x679dd514582f9fcf,
        0x0f6d2b697bd44da8,
        0x77e36f7304c48942,
        0x3f9d85a86a1d36c8,
        0x1112e6ad91d692a1,
    ];

    const INITIAL_VALUES_512_256: [u64; 8] = [
        0x22312194fc2bf72c,
        0x9f555fa3c84c64c2,
        0x2393b86b6f53b151,
        0x963877195940eabd,
        0x96283ee2a88effe3,
        0xbe5e1e2553863992,
        0x2b0199fc2c85b8aa,
        0x0eb72ddc81c52ca2,
    ];

    #[repr(C)]
    union MsgSch<const B: usize, const W: usize, T: Copy> {
        b: [u8; B],
        w: [T; W],
    }

    impl<const B: usize, const W: usize, T: Copy> MsgSch<B, W, T> {
        fn new() -> Self {
            MsgSch { b: [0; B] }
        }
    }

    pub struct Context<const B: usize, const W: usize, const S: usize, T: Copy + 'static + Default> {
        st: [T; 8],
        msg_sch: MsgSch<B, W, T>,
        msg_num: usize,
        len: usize,
        _t: PhantomData<usize>,
    }

    macro_rules! new_context {
        ($initial_values:ident) => {
            Self {
                st: $initial_values,
                msg_sch: MsgSch::new(),
                msg_num: 0,
                len: 0,
                _t: PhantomData,
            }
        };
    }

    /// Extend the first 16 words into the remaining words of the message schedule
    /// Parameters are as follows:
    ///    $s - A mutable reference to a Context struct
    ///    $typ - The unsigned integer type used for calculations (u32 or u64)
    ///    $msg_sch_len - The number of words in $s.msg_sch
    ///    $r1 to $ r6 - Integers used in bitwise operations performed by sigma0 and sigma1
    macro_rules! extend_msg_schedule {
        ($s:ident, $typ:ty, $msg_sch_len:literal, $r1:literal, $r2:literal, $r3:literal, $r4:literal, $r5:literal, $r6:literal) => {
            for i in 0..($msg_sch_len - 16) {
                let w0: $typ = $s.msg_sch.w[i].to_be();
                let mut w1: $typ = $s.msg_sch.w[i + 1].to_be();
                w1 = w1.rotate_right($r1) ^ w1.rotate_right($r2) ^ (w1 >> $r3); //sigma0
                let w9: $typ = $s.msg_sch.w[i + 9].to_be();
                let mut w14: $typ = $s.msg_sch.w[i + 14].to_be();
                w14 = w14.rotate_right($r4) ^ w14.rotate_right($r5) ^ (w14 >> $r6); //sigma1
                $s.msg_sch.w[i + 16] = w0
                    .wrapping_add(w1.wrapping_add(w9.wrapping_add(w14)))
                    .to_be();
            }
        };
    }

    /// This is the main compression loop
    /// Parameters are as follows:
    ///    $s - A mutable reference to a Context struct
    ///    $typ - The unsigned integer type used for calculations (u32 or u64)
    ///    $constants - The array of constants used in the calculation
    ///    $r1 to $ r6 - Integers used in bitwise operations performed by Sigma0 and Sigma1
    macro_rules! compression_loop {
        ($s:ident, $typ:ty, $constants:ident, $r1:literal, $r2:literal, $r3:literal, $r4:literal, $r5:literal, $r6:literal) => {
            // set the working variables to the hash values
            let mut a: $typ = $s.st[0];
            let mut b: $typ = $s.st[1];
            let mut c: $typ = $s.st[2];
            let mut d: $typ = $s.st[3];
            let mut e: $typ = $s.st[4];
            let mut f: $typ = $s.st[5];
            let mut g: $typ = $s.st[6];
            let mut h: $typ = $s.st[7];

            // the "compression loop"
            for (i, constant) in $constants.iter().enumerate() {
                let sigma0: $typ = a.rotate_right($r1) ^ a.rotate_right($r2) ^ a.rotate_right($r3); // Sigma0
                let sigma1: $typ = e.rotate_right($r4) ^ e.rotate_right($r5) ^ e.rotate_right($r6); // Sigma1
                let choice: $typ = (e & f) ^ ((e ^ <$typ>::MAX) & g); // Ch
                let majority: $typ = (a & b) ^ (a & c) ^ (b & c); // Maj
                let temp1: $typ = h.wrapping_add(sigma1.wrapping_add(
                    choice.wrapping_add(constant.wrapping_add($s.msg_sch.w[i].to_be())),
                ));
                let temp2: $typ = sigma0.wrapping_add(majority);
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
            $s.st[0] = $s.st[0].wrapping_add(a);
            $s.st[1] = $s.st[1].wrapping_add(b);
            $s.st[2] = $s.st[2].wrapping_add(c);
            $s.st[3] = $s.st[3].wrapping_add(d);
            $s.st[4] = $s.st[4].wrapping_add(e);
            $s.st[5] = $s.st[5].wrapping_add(f);
            $s.st[6] = $s.st[6].wrapping_add(g);
            $s.st[7] = $s.st[7].wrapping_add(h);
        };
    }

    macro_rules! transform {
        ($s:ident, $data:ident, $chunk_len:literal, $extend:tt, $compress:tt) => {
            let mut bytes_copied: usize = 0;
            while bytes_copied < $data.len() {
                let len: usize = ($data.len() - bytes_copied).min($chunk_len - $s.msg_num);
                $s.msg_sch.b[$s.msg_num..($s.msg_num + len)]
                    .clone_from_slice(&$data[bytes_copied..(bytes_copied + len)]);
                bytes_copied += len;
                $s.msg_num += len;
                $s.len += len;
                if $s.msg_num == $chunk_len {
                    $extend;
                    $compress;
                    $s.msg_sch.b.fill(0); // is this necessary?
                    $s.msg_num = 0;
                }
            }
        };
    }

    macro_rules! wrap_up {
        ($s:ident, $typ:ty, $digest:ident, $digest_len:literal, $chunk_len:literal) => {
            if $digest.len() != $digest_len {
                Err(crate::error::Error::InvalidDigestLength($digest_len))
            } else {
                let mut buf: Vec<u8> = Vec::new();
                buf.push(128u8);
                while (buf.len() + $s.msg_num + std::mem::size_of::<$typ>()) % $chunk_len != 0 {
                    buf.push(0u8);
                }
                buf.extend_from_slice(&(($s.len * 8) as $typ).to_be_bytes());
                $s.update(&buf);
                for (i, w) in $digest
                    .chunks_exact_mut(std::mem::size_of::<$typ>() / 2)
                    .enumerate()
                {
                    w.clone_from_slice(&$s.st[i].to_be_bytes());
                }
                Ok(())
            }
        };
    }

    pub type Sha224 = Context<256, 64, 28, u32>;

    impl super::OneWayHash for Sha224 {
        #[inline]
        fn init() -> Self {
            new_context!(INITIAL_VALUES_224)
        }

        #[inline]
        fn reset(&mut self) {
            self.st = INITIAL_VALUES_224;
            self.msg_sch = MsgSch { b: [0; 256] };
            self.msg_num = 0;
            self.len = 0;
        }

        #[inline]
        fn update(&mut self, data: &[u8]) -> &mut Self {
            unsafe {
                transform!(
                    self,
                    data,
                    64,
                    {
                        extend_msg_schedule!(self, u32, 64, 7, 18, 3, 17, 19, 10);
                    },
                    {
                        compression_loop!(self, u32, CONSTANTS_256, 2, 13, 22, 6, 11, 25);
                    }
                );
                self
            }
        }

        #[inline]
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            wrap_up!(self, u64, digest, 28, 64)
        }
    }

    pub type Sha256 = Context<256, 64, 32, u32>;

    impl super::OneWayHash for Sha256 {
        #[inline]
        fn init() -> Self {
            new_context!(INITIAL_VALUES_256)
        }

        #[inline]
        fn reset(&mut self) {
            self.st = INITIAL_VALUES_256;
            self.msg_sch = MsgSch { b: [0; 256] };
            self.msg_num = 0;
            self.len = 0;
        }

        #[inline]
        fn update(&mut self, data: &[u8]) -> &mut Self {
            unsafe {
                transform!(
                    self,
                    data,
                    64,
                    {
                        extend_msg_schedule!(self, u32, 64, 7, 18, 3, 17, 19, 10);
                    },
                    {
                        compression_loop!(self, u32, CONSTANTS_256, 2, 13, 22, 6, 11, 25);
                    }
                );
                self
            }
        }

        #[inline]
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            wrap_up!(self, u64, digest, 32, 64)
        }
    }

    pub type Sha384 = Context<320, 80, 48, u64>;

    impl super::OneWayHash for Sha384 {
        #[inline]
        fn init() -> Self {
            new_context!(INITIAL_VALUES_384)
        }

        #[inline]
        fn reset(&mut self) {
            self.st = INITIAL_VALUES_384;
            self.msg_sch = MsgSch { b: [0; 320] };
            self.msg_num = 0;
            self.len = 0;
        }

        #[inline]
        fn update(&mut self, data: &[u8]) -> &mut Self {
            unsafe {
                transform!(
                    self,
                    data,
                    128,
                    {
                        extend_msg_schedule!(self, u64, 80, 1, 8, 7, 19, 61, 6);
                    },
                    {
                        compression_loop!(self, u64, CONSTANTS_512, 28, 34, 39, 14, 18, 41);
                    }
                );
                self
            }
        }

        #[inline]
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            wrap_up!(self, u128, digest, 48, 128)
        }
    }

    pub type Sha512 = Context<320, 80, 64, u64>;

    impl super::OneWayHash for Sha512 {
        #[inline]
        fn init() -> Self {
            new_context!(INITIAL_VALUES_512)
        }

        #[inline]
        fn reset(&mut self) {
            self.st = INITIAL_VALUES_512;
            self.msg_sch = MsgSch { b: [0; 320] };
            self.msg_num = 0;
            self.len = 0;
        }

        #[inline]
        fn update(&mut self, data: &[u8]) -> &mut Self {
            unsafe {
                transform!(
                    self,
                    data,
                    128,
                    {
                        extend_msg_schedule!(self, u64, 80, 1, 8, 7, 19, 61, 6);
                    },
                    {
                        compression_loop!(self, u64, CONSTANTS_512, 28, 34, 39, 14, 18, 41);
                    }
                );
                self
            }
        }

        #[inline]
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            wrap_up!(self, u128, digest, 64, 128)
        }
    }

    pub type Sha512_224 = Context<320, 80, 28, u64>;

    impl super::OneWayHash for Sha512_224 {
        #[inline]
        fn init() -> Self {
            new_context!(INITIAL_VALUES_512_224)
        }

        #[inline]
        fn reset(&mut self) {
            self.st = INITIAL_VALUES_512_224;
            self.msg_sch = MsgSch { b: [0; 320] };
            self.msg_num = 0;
            self.len = 0;
        }

        #[inline]
        fn update(&mut self, data: &[u8]) -> &mut Self {
            unsafe {
                transform!(
                    self,
                    data,
                    128,
                    {
                        extend_msg_schedule!(self, u64, 80, 1, 8, 7, 19, 61, 6);
                    },
                    {
                        compression_loop!(self, u64, CONSTANTS_512, 28, 34, 39, 14, 18, 41);
                    }
                );
                self
            }
        }

        #[inline]
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            wrap_up!(self, u128, digest, 28, 128)?;
            // fill in the last four bytes
            digest[24..28].clone_from_slice(&self.st[3].to_be_bytes()[0..4]);
            Ok(())
        }
    }

    pub type Sha512_256 = Context<320, 80, 32, u64>;

    impl super::OneWayHash for Sha512_256 {
        #[inline]
        fn init() -> Self {
            new_context!(INITIAL_VALUES_512_256)
        }

        #[inline]
        fn reset(&mut self) {
            self.st = INITIAL_VALUES_512_256;
            self.msg_sch = MsgSch { b: [0; 320] };
            self.msg_num = 0;
            self.len = 0;
        }

        #[inline]
        fn update(&mut self, data: &[u8]) -> &mut Self {
            unsafe {
                transform!(
                    self,
                    data,
                    128,
                    {
                        extend_msg_schedule!(self, u64, 80, 1, 8, 7, 19, 61, 6);
                    },
                    {
                        compression_loop!(self, u64, CONSTANTS_512, 28, 34, 39, 14, 18, 41);
                    }
                );
                self
            }
        }

        #[inline]
        fn finish(&mut self, digest: &mut [u8]) -> crate::error::Result<()> {
            wrap_up!(self, u128, digest, 32, 128)
        }
    }
}
