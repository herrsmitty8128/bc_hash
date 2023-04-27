// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

pub mod digest;
pub mod error;
pub mod io;
pub mod merkle;
pub mod sha2;
pub mod sha3;
use error::Result;
use merkle::Proof;
use std::ops::Range;

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

pub trait Block
where
    Self: Sized,
{
    /// Transmutate an object into an array of bytes.
    fn serialize(&self, buf: &mut [u8]) -> error::Result<()>;

    /// Transmutate an array of bytes into a new object.
    fn deserialize(buf: &[u8]) -> error::Result<Self>;
}

pub trait DataLayer<const DIGEST_SIZE: usize, const BLOCK_SIZE: usize, T, H>
where
    T: Block,
    H: OneWayHasher<DIGEST_SIZE>,
{
    /// Returns the current block count.
    fn count(&self) -> u64;

    /// Validates a ranges of blocks.
    fn validate(&self, range: Range<usize>) -> Result<()>;

    /// Appends a collection of blocks to the end of the blockchain.
    fn append(&self) -> Result<()>;

    /// Returns the state (hash digest of the last block) of the blockchain.
    fn state(&self) -> Result<()>;

    /// Returns a merkle proof for the record at ```index`` in ```block```.
    fn prove(&self, block: usize, index: usize) -> Result<Proof<DIGEST_SIZE>>;

    /// Returns a block.
    fn get(&self);
}
