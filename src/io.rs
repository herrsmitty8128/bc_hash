// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

use crate::{
    error::{Error, Result},
    OneWayHasher,
};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    marker::PhantomData,
    path::Path,
    vec,
};

/// Returns Ok(()) if the file is not empty and the total files size is an even multiple of the block size.
fn validate_size(file: &File, block_size: usize) -> Result<()> {
    let size: u64 = file.metadata()?.len();
    if size == 0 {
        Err(Error::FileIsEmpty)
    } else if size % block_size as u64 != 0 {
        Err(Error::InvalidFileSize)
    } else {
        Ok(())
    }
}

/// Returns the size of the underlying blockchain file in bytes.
fn file_size(file: &File) -> Result<u64> {
    Ok(file.metadata()?.len())
}

/// Returns the total number of blocks in the underlying blockchain file.
fn block_count(file: &File, block_size: usize) -> Result<u64> {
    let file_size: u64 = file_size(file)?;
    if file_size == 0 {
        Err(Error::FileIsEmpty)
    } else if file_size % block_size as u64 != 0 {
        Err(Error::InvalidFileSize)
    } else {
        Ok(file_size / block_size as u64)
    }
}

/// A struct that wraps a ```io::Bufreader```
#[derive(Debug)]
pub struct Reader<const MDLEN: usize, const DATALEN: usize, H>
where
    H: OneWayHasher<MDLEN>,
{
    inner: BufReader<File>,
    _h: PhantomData<H>,
}

impl<const MDLEN: usize, const DATALEN: usize, H> Reader<MDLEN, DATALEN, H>
where
    H: OneWayHasher<MDLEN>,
{
    /// Creates and returns a new reader object.
    pub fn new(path: &Path) -> Result<Reader<MDLEN, DATALEN, H>> {
        let file: File = File::options().write(false).read(true).open(path)?;
        validate_size(&file, Self::block_size())?;
        Ok(Self {
            inner: BufReader::new(file),
            _h: PhantomData,
        })
    }

    /// Returns the block size for the underlying blockchain in bytes.
    #[inline]
    pub fn block_size() -> usize {
        MDLEN + DATALEN
    }

    /// Returns the total number of blocks in the stream.
    #[inline]
    pub fn block_count(&self) -> Result<u64> {
        block_count(self.inner.get_ref(), Self::block_size())
    }

    /// Returns the total size of the stream in bytes.
    #[inline]
    pub fn stream_size(&self) -> Result<u64> {
        file_size(self.inner.get_ref())
    }

    /// Returns the current position in the byte stream. If the position is not an even
    /// multiple of the block size, then Err(Error::BadStreamPosition(pos)) is returned.
    #[inline]
    pub fn stream_position(&mut self) -> Result<u64> {
        let pos: u64 = self.inner.stream_position()?;
        let block_size: u64 = Self::block_size() as u64;
        if pos % block_size != 0 {
            Err(Error::BadStreamPosition(pos))
        } else {
            Ok(pos)
        }
    }

    /// Calls ```rewind()``` on the underlying file.
    pub fn rewind(&mut self) -> Result<()> {
        self.inner.rewind().map_err(Error::from)
    }

    /// Calls ```seek()``` on the underlying file.
    pub fn seek(&mut self, index: u64) -> Result<u64> {
        let pos: u64 = index
            .checked_mul(Self::block_size() as u64)
            .ok_or(Error::IntegerOverflow)?;
        self.inner.seek(SeekFrom::Start(pos)).map_err(Error::from)
    }

    /// Reads the entire block located at the current stream position and copies it into ```buf```.
    /// Returns Ok(()) on success, or Err(Error) on failure. The length of ```buf```
    /// must be exactly equal to the total block size.
    pub fn read_block(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.len() != Self::block_size() {
            Err(Error::InvalidSliceLength)
        } else {
            self.inner.read_exact(buf).map_err(Error::from)
        }
    }

    /// Reads the entire block located at ```index``` and copies it into ```buf```.
    /// Returns Ok(()) on success, or Err(Error) on failure. The length of ```buf```
    /// must be exactly equal to the total block size.
    pub fn read_block_at(&mut self, index: u64, buf: &mut [u8]) -> Result<()> {
        self.seek(index)?;
        self.read_block(buf)
    }

    pub fn read_last_block(&mut self, buf: &mut [u8]) -> Result<()> {
        let pos: u64 = file_size(self.inner.get_ref())? - Self::block_size() as u64;
        self.inner.seek(SeekFrom::Start(pos))?;
        self.inner.read_exact(buf)?;
        Ok(())
    }

    /// Reads the data section of the block located at the current stream position and
    /// copies it into ```buf```. Returns Ok(()) on success, or Err(Error) on failure.
    /// The length of ```buf``` must be exactly equal to the total block size minus the
    /// size of a SHA-256 digest (32 bytes).
    pub fn read_data(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.len() != DATALEN {
            Err(Error::InvalidSliceLength)
        } else {
            self.inner.seek(SeekFrom::Current(MDLEN as i64))?;
            self.inner.read_exact(buf).map_err(Error::from)
        }
    }

    /// Reads the data section of of the block located at ```index``` and copies it into ```buf```.
    /// Returns Ok(()) on success, or Err(Error) on failure. The length of ```buf``` must be
    /// exactly equal to the total block size minus the size of a SHA-256 digest (32 bytes).
    pub fn read_data_at(&mut self, index: u64, buf: &mut [u8]) -> Result<()> {
        self.seek(index)?;
        self.read_data(buf)
    }

    /// Calculates the hash of the block located at ```index - 1``` and compares
    /// it to the previous block's hash stored in the block located at ```index```.
    /// Returns Ok(()) if the hashs are identical, or Err(Error::InvalidBlockHash(index)) if not.
    pub fn validate_block_at(&mut self, index: u64) -> Result<()> {
        let block_size: usize = Self::block_size();
        if index >= self.block_count()? {
            Err(Error::BlockNumDoesNotExist)
        } else if index == 0 {
            Ok(()) // the genisis block is inherently always valid
        } else {
            let pos: u64 = (index - 1)
                .checked_mul(block_size as u64)
                .ok_or(Error::IntegerOverflow)?;
            self.inner.seek(SeekFrom::Start(pos))?;
            let mut buf: Vec<u8> = vec![0; block_size];
            self.inner.read_exact(&mut buf[0..block_size])?;
            let mut prev_digest: [u8; MDLEN] = [0; MDLEN];
            let mut hasher: H = H::init();
            hasher.update(&buf[0..block_size]).finish(&mut prev_digest);
            self.inner.read_exact(&mut buf[0..MDLEN])?;
            if buf[0..MDLEN] != prev_digest[..] {
                Err(Error::InvalidBlockHash(index))
            } else {
                Ok(())
            }
        }
    }

    /// Iterates over each block in the range [1..], calculates the hash of the previous block, and
    /// compares it to the previous block hash stored in the current block. If it encounters two hashs
    /// that are not identical, then Err(Error::InvalidBlockHash(b)) is returned. Otherwise Ok(())
    /// is returned when the iteration is complete.
    pub fn validate_all_blocks(&mut self) -> Result<()> {
        let mut hasher: H = H::init();
        let mut prev_digest: [u8; MDLEN] = [0; MDLEN];
        let block_size: usize = Self::block_size();
        let block_count: u64 = self.block_count()?;
        self.inner.rewind()?;
        let mut buf: Vec<u8> = vec![0; block_size];
        self.inner.read_exact(&mut buf[0..block_size])?; // read the genisis block
        for b in (0..block_count).skip(1) {
            hasher.reset();
            hasher.update(&buf[0..block_size]).finish(&mut prev_digest);
            self.inner.read_exact(&mut buf[0..block_size])?;
            if buf[0..MDLEN] != prev_digest[..] {
                return Err(Error::InvalidBlockHash(b));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Writer<const MDLEN: usize, const DATALEN: usize, H>
where
    H: OneWayHasher<MDLEN>,
{
    inner: BufWriter<File>,
    prev_hash: [u8; MDLEN],
    _h: PhantomData<H>,
}

impl<const MDLEN: usize, const DATALEN: usize, H> Writer<MDLEN, DATALEN, H>
where
    H: OneWayHasher<MDLEN>,
{
    /// Creates and returns an new ```Writer```.
    pub fn new(path: &Path) -> Result<Self> {
        if !path.is_file() {
            Err(Error::PathIsNotAFile)
        } else if DATALEN == 0 || DATALEN > (u32::MAX as usize - MDLEN) {
            Err(Error::InvalidDataLength(DATALEN))
        } else if MDLEN == 0 || MDLEN > (u32::MAX as usize - DATALEN) {
            Err(Error::InvalidDigestLength(MDLEN))
        } else if path.exists() {
            let mut prev_hash: [u8; MDLEN] = [0; MDLEN];
            let block_size: usize = Self::block_size();
            let mut buf: Vec<u8> = vec![0; block_size];
            let mut reader: Reader<MDLEN, DATALEN, H> = Reader::new(path).unwrap();
            if reader.stream_size()? != 0 {
                reader.read_last_block(&mut buf)?;
                H::init().update(&buf[0..block_size]).finish(&mut prev_hash);
            }
            let file: File = File::options().write(true).read(false).open(path)?;
            validate_size(&file, block_size)?;
            Ok(Self {
                inner: BufWriter::new(file),
                prev_hash,
                _h: PhantomData,
            })
        } else {
            Ok(Self {
                inner: BufWriter::new(
                    File::options()
                        .write(true)
                        .read(false)
                        .create_new(true)
                        .open(path)?,
                ),
                prev_hash: [0; MDLEN],
                _h: PhantomData,
            })
        }
    }

    /// Returns the block size for the underlying blockchain in bytes.
    #[inline]
    pub fn block_size() -> usize {
        MDLEN + DATALEN
    }

    /// Returns the total number of blocks in the stream.
    #[inline]
    pub fn block_count(&self) -> Result<u64> {
        block_count(self.inner.get_ref(), Self::block_size())
    }

    /// Returns the total size of the stream in bytes.
    #[inline]
    pub fn stream_size(&self) -> Result<u64> {
        file_size(self.inner.get_ref())
    }

    /// Returns the current position in the byte stream. If the position is not an even
    /// multiple of the block size, then Err(Error::BadStreamPosition(pos)) is returned.
    #[inline]
    pub fn stream_position(&mut self) -> Result<u64> {
        let pos: u64 = self.inner.stream_position()?;
        let block_size: u64 = Self::block_size() as u64;
        if pos % block_size != 0 {
            Err(Error::BadStreamPosition(pos))
        } else {
            Ok(pos)
        }
    }

    /// Writes a new block to the end of the stream. You need not concern yourself with the previous
    /// block hash when calling this method. ```Writer``` takes care of this for you. The ```data`` arg
    /// should contains the serialized data section of the new block. As suchy, the length of ```data```
    /// must be exactly equal to the total block size minus the size of a SHA-256 digest (32 bytes).
    /// If not, then Err(Error::InvalidSliceLength) is returned.
    pub fn append(&mut self, data: &mut [u8]) -> Result<()> {
        let block_size: usize = Self::block_size();
        if data.len() != DATALEN {
            Err(Error::InvalidSliceLength)
        } else {
            self.inner.seek(SeekFrom::End(0))?;
            self.inner.write_all(&self.prev_hash)?;
            self.inner.write_all(data)?;
            self.inner.flush()?;
            H::init()
                .update(&self.prev_hash[..])
                .update(&data[0..block_size])
                .finish(&mut self.prev_hash);
            Ok(())
        }
    }
}
