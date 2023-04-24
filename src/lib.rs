// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

pub mod digest;
pub mod error;
pub mod io;
pub mod merkle;
pub mod sha2;
pub mod sha3;

pub trait OneWayHasher<const MDLEN: usize>: std::io::Write
where
    Self: Sized,
{
    fn init() -> Self;
    fn reset(&mut self) -> &mut Self;
    fn update(&mut self, data: &[u8]) -> &mut Self;
    fn finish(&mut self, digest: &mut [u8; MDLEN]);
}

pub trait FinishXOF
where
    Self: Sized,
{
    fn finish_xof(&mut self, digest: &mut [u8]);
}

pub trait BlockData {
    /// Transmutate an object into an array of bytes.
    fn serialize(&self, buf: &mut [u8]) -> error::Result<()>;

    /// Transmutate an array of bytes into a new object.
    fn deserialize(buf: &[u8]) -> error::Result<Self>
    where
        Self: Sized;
}

pub trait DataLayer<const DIGEST_SIZE: usize, const BLOCK_SIZE: usize, T, H>
where
    T: BlockData,
    H: OneWayHasher<DIGEST_SIZE>,
{
    // need to implement
}
