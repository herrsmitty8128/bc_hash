/// *sha2* is a library of SHA2 algorithms written in Rust.
pub mod sha256 {
    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::path::Path;
    use std::ptr::copy_nonoverlapping;

    /// The number of u32 values in a SHA-256 digest.
    pub const DIGEST_WORDS: usize = 8;

    /// The number of bytes in a SHA-256 digest.
    pub const DIGEST_BYTES: usize = DIGEST_WORDS * std::mem::size_of::<u32>();

    /// number of bytes in a 512-bit block
    const BLOCK_SIZE: usize = 512 / 8;

    /// The first 32 bits of the fractional parts of the cube roots of the first 64 primes 2 through 311.
    const CONSTANTS: [u32; 64] = [
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
    const INITIAL_VALUES: [u32; DIGEST_WORDS] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    /// Represents the message schedule buffer used in the processing of the SHA-256 algorithm.
    struct MsgSch {
        w: [u32; 64],
    }

    impl Default for MsgSch {
        fn default() -> Self {
            Self { w: [0; 64] }
        }
    }

    impl MsgSch {
        // Copies the 512-bit block from the buffer located at *index* into the 1st 16 words w[0..15] of the message schedule.
        pub fn load_block(&mut self, buf: &mut Vec<u8>, index: usize) {
            self.w.fill(0);
            unsafe {
                let mut ptr: *mut u32 = buf.as_mut_ptr().add(index) as *mut u32;
                for j in 0..16 {
                    self.w[j] = (*ptr).to_be(); // Covert everything to big-endian
                    ptr = ptr.add(1);
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    /// Represents a SHA-256 digest in binary format.
    pub struct Digest {
        data: [u32; DIGEST_WORDS],
    }

    impl Eq for Digest {}

    impl PartialEq for Digest {
        fn eq(&self, other: &Self) -> bool {
            for i in 0..DIGEST_WORDS {
                if self.data[i] != other.data[i] {
                    return false;
                }
            }
            true
        }

        #[allow(clippy::partialeq_ne_impl)]
        fn ne(&self, other: &Self) -> bool {
            !self.eq(other)
        }
    }

    impl Default for Digest {
        /// Creates a new SHA-256 digest whose data buffer is initialized with zeros.
        fn default() -> Self {
            Self::new()
        }
    }

    impl ToString for Digest {
        /// Returns a string consisting of 64-character hexidecimal representation of the digest.
        fn to_string(&self) -> String {
            let mut dst: String = String::new();
            for n in self.data {
                dst.push_str(&format!("{:08x}", n));
            }
            dst
        }
    }

    impl TryFrom<&Path> for Digest {
        type Error = std::io::Error;
        /// Attempts to open a file, read all of its contents into a buffer, then calculate and
        /// return a new SHA-256 digest. Ok(Digest) is returned on success. Err(io::Error) is returned
        /// on failure. The *path* argument must contain the path and file name of the file for
        /// which the digest should be calculated.
        fn try_from(path: &Path) -> Result<Self, Self::Error> {
            let mut reader: BufReader<File> = BufReader::new(File::open(path)?);
            let buf: &mut Vec<u8> = &mut Vec::new();
            reader.read_to_end(buf)?;
            Ok(Self::from(buf))
        }
    }

    impl TryFrom<&str> for Digest {
        type Error = &'static str;
        /// Attempts to create a new sha-256 digest from the string argument. The string must be 64 characters
        /// in hexidecimal format and may include the "0x" prefix. Ok(Digest) is returned on success. Err(String)
        /// is returned on failure.
        fn try_from(string: &str) -> Result<Self, Self::Error> {
            let s: String = string.to_ascii_lowercase();
            let mut src: &str = s.trim();
            if let Some(s) = src.strip_prefix("0x") {
                src = s
            }
            if src.len() == 64 {
                let mut digest = Digest::default();
                for (i, offset) in (0..64).step_by(8).enumerate() {
                    digest.data[i] = u32::from_str_radix(&src[offset..(offset + 8)], 16)
                        .map_err(|_| "Error parsing hex string.")?;
                }
                Ok(digest)
            } else {
                Err("Found string length {}, expected length 64.")
            }
        }
    }

    impl From<&[u8]> for Digest {
        fn from(bytes: &[u8]) -> Self {
            let mut buf: Vec<u8> = Vec::from(bytes);
            Self::from(&mut buf)
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

    impl Digest {
        /// Creates a new digest whose buffer is initialized to the first 32 bits of the fractional parts of the square roots of the first 8 primes, 2 through 19.
        pub fn new() -> Self {
            Self {
                data: INITIAL_VALUES,
            }
        }

        /// Attempts to create a new digest by cloning the buffer. If buffer.len() is not greater than or equal to DIGEST_BYTES, the Err(()) will be returned. Otherwise, Ok(Digest) will be returned.
        pub fn from_bytes(buffer: &[u8]) -> Result<Digest, String> {
            if buffer.len() >= DIGEST_BYTES {
                let digest: Digest = Digest {
                    data: [0; DIGEST_WORDS],
                };
                unsafe {
                    copy_nonoverlapping(
                        buffer.as_ptr(),
                        digest.data.as_ptr() as *mut u8,
                        DIGEST_BYTES,
                    );
                }
                Ok(digest)
            } else {
                Err(format!(
                    "Found slice &[u8] with length {}, expected length >= {}.",
                    buffer.len(),
                    DIGEST_BYTES
                ))
            }
        }

        /// Resets the digest's data buffer to the first 32 bits of the fractional parts of the square roots of the first 8 primes, 2 through 19.
        pub fn reset(&mut self) {
            self.data = INITIAL_VALUES;
        }

        /// Attempts to transmute the digest's underlying buffer from [u32] to &[u8]. Returns Ok(&[u8]) on success or Err(&str) on failure.
        pub fn as_bytes(&mut self) -> Result<&[u8], &str> {
            let x: (&[u32], &[u8], &[u32]) = unsafe { self.data.align_to::<u8>() };
            if x.0.is_empty() && x.1.len() == DIGEST_BYTES && x.2.is_empty() {
                Ok(x.1)
            } else {
                Err("Failed to properly align the data buffer.")
            }
        }

        /// A convenience function to print the text representation of the digest in hexidecimal format to stdio.
        pub fn print(&self) {
            for x in self.data {
                print!("{:08x}", x);
            }
        }

        /// Calculates the SHA-256 digest from a vector of bytes and writes it to the digest's data buffer.
        pub fn calculate(digest: &mut Digest, buf: &mut Vec<u8>) {
            let len: usize = buf.len();
            digest.reset();
            let mut msg_sch: MsgSch = MsgSch::default();
            Self::will_start_chunk_loop(buf, len);
            // break the message block into 512-bit chunks. This is the "chunk loop"
            for index in (0..buf.len()).step_by(BLOCK_SIZE) {
                msg_sch.load_block(buf, index);
                digest.update(&mut msg_sch);
            }
            Self::did_finish_chunk_loop(buf, len);
        }

        fn will_start_chunk_loop(buf: &mut Vec<u8>, len: usize) {
            // append a single "1" to the buffer
            buf.push(128u8);

            // round the buffer to nearest multiple of 512 bits while leaving room for 8 more bytes
            while (buf.len() + 8) % BLOCK_SIZE != 0 {
                buf.push(0u8);
            }

            // convert the bit count of the buffer into an 8-byte array in big endian format and append it to the buffer
            buf.extend_from_slice(&((len * 8) as u64).to_be_bytes());
        }

        fn did_finish_chunk_loop(buf: &mut Vec<u8>, len: usize) {
            // remove all the bytes that we added to the end of the buffer
            buf.truncate(len);
        }

        /// Updates the value of the digest based on the contents of the message schedule.
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
