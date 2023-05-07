// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

pub mod cache;
pub mod digest;
pub mod error;
pub mod io;
pub mod merkle;
pub mod sha2;
pub mod sha3;
use digest::Digest;
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

pub trait Block<const DIGEST_SIZE: usize, const BLOCK_SIZE: usize, H>
where
    Self: Default + Sized,
    H: OneWayHasher<DIGEST_SIZE>,
{
    /// Calculate self's hash and write it to digest. Returns Ok(())
    /// on success or Err(error::Error) on failure.
    fn calc_hash(&self, digest: &mut [u8]) -> error::Result<()>;

    /// Return the previous block's hash digest as a slice
    fn prev_hash<'a>(&self) -> error::Result<&'a [u8]>;

    /// Transmutate an object into an array of bytes.
    fn encode(&self, buf: &mut [u8]) -> error::Result<()>;

    /// Transmutate an array of bytes into a new object.
    fn decocde(buf: &[u8]) -> error::Result<Self>;

    /// Returns the size of an encoded block in bytes.
    fn size() -> usize {
        BLOCK_SIZE
    }

    /// Returns in the size of a digest in bytes.
    fn digest_size() -> usize {
        DIGEST_SIZE
    }
}

pub trait BlockChainDB<const DIGEST_SIZE: usize, const BLOCK_SIZE: usize, H, T>
where
    Self: Default + Sized,
    T: Block<DIGEST_SIZE, BLOCK_SIZE, H>,
    H: OneWayHasher<DIGEST_SIZE>,
{
    /// Returns the current block count.
    fn count(&self) -> u64;

    /// Validates a ranges of blocks.
    fn validate(&self, range: Range<usize>) -> Result<()>;

    /// Appends a collection of blocks to the end of the blockchain.
    fn append(&self) -> Result<()>;

    /// Returns the state (hash digest of the last block) of the blockchain.
    fn state(&self) -> Result<Digest<DIGEST_SIZE>>;

    /// Returns a merkle proof for the record at ```index`` in ```block```.
    fn prove(&self, block: usize, index: usize) -> Result<Proof<DIGEST_SIZE>>;

    /// Returns a block.
    fn get(&self, block_num: u64) -> &[u8; BLOCK_SIZE];
}
