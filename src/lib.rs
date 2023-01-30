/// *sha2* is a library of SHA2 algorithms written in Rust.
pub mod sha256 {
    use std::fs::File;
    use std::io::{BufReader, Read};

    /// number of bytes in a 512-bit block
    const BLOCK_SIZE: usize = 512 / 8;

    /// The first 32 bits of the fractional parts of the cube roots of the first 64 primes 2 through 311.
    const SHA256_CONSTANTS: [u32; 64] = [
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
                let mut ptr = buf.as_mut_ptr().add(index) as *mut u32;
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
        data: [u32; 8],
    }

    impl Eq for Digest {}

    impl PartialEq for Digest {
        fn eq(&self, other: &Self) -> bool {
            for i in 0..8 {
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
        /// Creates a new SHA-256 digest initialized with the first 32 bits of the
        /// fractional parts of the square roots of the first 8 primes, 2 through 19.
        fn default() -> Self {
            Self::new()
        }
    }

    impl Digest {
        /// Creates a new SHA-256 digest initialized with the first 32 bits of the
        /// fractional parts of the square roots of the first 8 primes, 2 through 19.
        pub fn new() -> Self {
            Self {
                data: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
                ],
            }
        }

        /// Prints the text representation of the digest in hexidecimal format to stdio.
        pub fn print_as_hex(&self) {
            for x in self.data {
                print!("{:08x}", x);
            }
        }

        /// Returns a new string containing the text representation of the digest in hexidecimal format.
        pub fn to_hex_string(&self) -> String {
            let mut dst: String = String::new();
            for n in self.data {
                dst.push_str(&format!("{:x}", n));
            }
            dst
        }

        /// Attempts to create a new sha-256 digest from the string argument. The string must be 64 characters
        /// in hexidecimal format. Ok(Digest) is returned on success. Err(String) is returned on failure.
        pub fn from_hex_string(string: &str) -> Result<Digest, String> {
            let lower: String = string.to_ascii_lowercase();
            let mut src: &str = lower.trim();
            if let Some(s) = src.strip_prefix("0x") {src = s}
            match src.len().cmp(&64) {
                std::cmp::Ordering::Greater => {
                    Err(String::from("String is longer then 64 characters."))
                }
                std::cmp::Ordering::Less => {
                    Err(String::from("String is shorter then 64 characters."))
                }
                _ => {
                    let mut digest = Digest::new();
                    for i in 0..8 {
                        let offset: usize = i * 8;
                        match u32::from_str_radix(&src[offset..(offset + 8)], 16) {
                            Ok(d) => digest.data[i] = d,
                            Err(e) => return Err(e.to_string()),
                        }
                    }
                    Ok(digest)
                }
            }
        }

        /// Attempts to open a file, read all of its contents into a buffer, then calculate and
        /// return a new SHA-256 digest. Ok(Digest) is returned on success. Err(String) is returned
        /// on failure. The *path* argument must contain the path and file name of the file for
        /// which the digest should be calculated.
        pub fn from_file(path: &String) -> Result<Digest, String> {
            match File::open(path) {
                Ok(inner) => {
                    let mut reader = BufReader::new(inner);
                    let buf: &mut Vec<u8> = &mut Vec::new();
                    match reader.read_to_end(buf) {
                        Ok(_) => Ok(Self::from_buffer(buf)),
                        Err(e) => Err(e.to_string()),
                    }
                }
                Err(e) => Err(e.to_string()),
            }
        }

        fn fix_up(buf: &mut Vec<u8>, size: usize) {
            // convert the size of the data into an array of bytes in big endian format
            let original_bit_count: [u8; 8] = ((size * 8) as u64).to_be_bytes();

            // append a single "1"
            buf.push(128u8);

            // round to nearest multiple of 512 bits but leave room for the integer size
            while (buf.len() + 8) % BLOCK_SIZE != 0 {
                buf.push(0u8);
            }

            // Append 64 bits to the end, where the 64 bits are a big-endian
            // integer representing the length of the original input in binary.
            buf.extend_from_slice(&original_bit_count);

            assert!(
                buf.len() % BLOCK_SIZE == 0,
                "buffer is not a multiple of block size"
            );
        }

        /// Calculates and returns a new SHA-256 digest from a vector of bytes.
        pub fn from_buffer(buf: &mut Vec<u8>) -> Digest {
            let mut digest: Digest = Digest::new();
            let mut msg_sch: MsgSch = MsgSch::default();
            Self::fix_up(buf, buf.len());
            // break the message block into 512-bit chunks. This is the "chunk loop"
            for index in (0..buf.len()).step_by(BLOCK_SIZE) {
                msg_sch.load_block(buf, index);
                digest.update(&mut msg_sch);
            }
            digest
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
            for (i, constant) in SHA256_CONSTANTS.iter().enumerate() {
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
