use crate::FinishXOF;
use crate::OneWayHash;
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
pub struct Context<const B: usize, const D: usize> {
    st: State,
    pt: usize,
    rsiz: usize,
    _s: PhantomData<usize>,
}

impl<const B: usize, const D: usize> Context<B, D> {
    fn init() -> Context<B, D> {
        Self {
            st: State { q: [0; 25] },
            pt: 0,
            rsiz: 200 - (2 * B),
            _s: PhantomData,
        }
    }

    /// update state with more data
    fn update(&mut self, data: &[u8]) {
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
        }
    }

    /// finalize and output a hash
    fn finish(&mut self, digest: &mut [u8; D]) {
        unsafe {
            self.st.b[self.pt] ^= 0x06;
            self.st.b[self.rsiz - 1] ^= 0x80;
            self.keccakf();
            digest.copy_from_slice(&self.st.b[..D]);
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

    fn shake_out(&mut self, digest: &mut [u8]) {
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

pub type Sha3_224 = Context<28, 28>;

impl OneWayHash<28> for Sha3_224 {
    #[inline]
    fn init() -> Sha3_224 {
        Context::<28, 28>::init()
    }

    #[inline]
    fn reset(&mut self) {
        self.st = State { q: [0; 25] };
        self.pt = 0;
        self.rsiz = 200 - (2 * 28);
    }

    #[inline]
    fn update(&mut self, data: &[u8]) -> &mut Sha3_224 {
        self.update(data);
        self
    }

    #[inline]
    fn finish(&mut self, digest: &mut [u8; 28]) {
        self.finish(digest)
    }
}

impl std::io::Write for Sha3_224 {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Context::update(self, bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub type Sha3_256 = Context<32, 32>;

impl OneWayHash<32> for Sha3_256 {
    #[inline]
    fn init() -> Sha3_256 {
        Context::<32, 32>::init()
    }

    #[inline]
    fn reset(&mut self) {
        self.st = State { q: [0; 25] };
        self.pt = 0;
        self.rsiz = 200 - (2 * 32);
    }

    #[inline]
    fn update(&mut self, data: &[u8]) -> &mut Sha3_256 {
        self.update(data);
        self
    }

    #[inline]
    fn finish(&mut self, digest: &mut [u8; 32]) {
        self.finish(digest)
    }
}

impl std::io::Write for Sha3_256 {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Context::update(self, bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub type Sha3_384 = Context<48, 48>;

impl OneWayHash<48> for Sha3_384 {
    #[inline]
    fn init() -> Sha3_384 {
        Context::<48, 48>::init()
    }

    #[inline]
    fn reset(&mut self) {
        self.st = State { q: [0; 25] };
        self.pt = 0;
        self.rsiz = 200 - (2 * 48);
    }

    #[inline]
    fn update(&mut self, data: &[u8]) -> &mut Sha3_384 {
        self.update(data);
        self
    }

    #[inline]
    fn finish(&mut self, digest: &mut [u8; 48]) {
        self.finish(digest)
    }
}

impl std::io::Write for Sha3_384 {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Context::update(self, bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub type Sha3_512 = Context<64, 64>;

impl OneWayHash<64> for Sha3_512 {
    #[inline]
    fn init() -> Sha3_512 {
        Context::<64, 64>::init()
    }

    #[inline]
    fn reset(&mut self) {
        self.st = State { q: [0; 25] };
        self.pt = 0;
        self.rsiz = 200 - (2 * 64);
    }

    #[inline]
    fn update(&mut self, data: &[u8]) -> &mut Sha3_512 {
        self.update(data);
        self
    }

    #[inline]
    fn finish(&mut self, digest: &mut [u8; 64]) {
        self.finish(digest)
    }
}

impl std::io::Write for Sha3_512 {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Context::update(self, bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct Shake128<const MDLEN: usize> {
    ctx: Context<16, MDLEN>,
}

impl<const MDLEN: usize> FinishXOF for Shake128<MDLEN> {
    fn finish_xof(&mut self, digest: &mut [u8]) {
        self.ctx.shake_xof();
        self.ctx.shake_out(digest)
    }
}

impl<const MDLEN: usize> OneWayHash<MDLEN> for Shake128<MDLEN> {
    #[inline]
    fn init() -> Shake128<MDLEN> {
        Shake128 {
            ctx: Context::<16, MDLEN>::init(),
        }
    }

    #[inline]
    fn reset(&mut self) {
        self.ctx.st = State { q: [0; 25] };
        self.ctx.pt = 0;
        self.ctx.rsiz = 200 - (2 * 16);
    }

    #[inline]
    fn update(&mut self, data: &[u8]) -> &mut Shake128<MDLEN> {
        self.ctx.update(data);
        self
    }

    #[inline]
    fn finish(&mut self, digest: &mut [u8; MDLEN]) {
        self.ctx.shake_xof();
        self.ctx.shake_out(digest)
    }
}

impl<const MDLEN: usize> std::io::Write for Shake128<MDLEN> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Context::update(&mut self.ctx, bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct Shake256<const MDLEN: usize> {
    ctx: Context<32, MDLEN>,
}

impl<const MDLEN: usize> FinishXOF for Shake256<MDLEN> {
    fn finish_xof(&mut self, digest: &mut [u8]) {
        self.ctx.shake_xof();
        self.ctx.shake_out(digest)
    }
}

impl<const MDLEN: usize> OneWayHash<MDLEN> for Shake256<MDLEN> {
    #[inline]
    fn init() -> Shake256<MDLEN> {
        Shake256 {
            ctx: Context::<32, MDLEN>::init(),
        }
    }

    #[inline]
    fn reset(&mut self) {
        self.ctx.st = State { q: [0; 25] };
        self.ctx.pt = 0;
        self.ctx.rsiz = 200 - (2 * 32);
    }

    #[inline]
    fn update(&mut self, data: &[u8]) -> &mut Shake256<MDLEN> {
        self.ctx.update(data);
        self
    }

    #[inline]
    fn finish(&mut self, digest: &mut [u8; MDLEN]) {
        self.ctx.shake_xof();
        self.ctx.shake_out(digest)
    }
}

impl<const MDLEN: usize> std::io::Write for Shake256<MDLEN> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Context::update(&mut self.ctx, bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
