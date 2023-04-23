// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

use std::{
    fs::File,
    io::{BufReader, BufWriter, Error, ErrorKind, Read, Result, Seek, SeekFrom, Write},
    path::Path,
};

pub const MAX_BLOCK_SIZE: u64 = u16::MAX as u64;

/// A struct that wraps a ```io::Bufreader```
#[derive(Debug)]
pub struct BlockReader<const BLOCK_SIZE: u64> {
    inner: BufReader<File>,
}

impl<const BLOCK_SIZE: u64> Read for BlockReader<BLOCK_SIZE> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() as u64 % BLOCK_SIZE != 0 {
            Err(Error::new(
                ErrorKind::Other,
                "Slice length is not a multiple of BLOCK_SIZE",
            ))
        } else if self.inner.seek(SeekFrom::Current(0))? % BLOCK_SIZE != 0 {
            Err(Error::new(
                ErrorKind::Other,
                "Stream position is not a multiple of BLOCK_SIZE",
            ))
        } else {
            self.inner.read_exact(buf)?;
            Ok(buf.len() / BLOCK_SIZE as usize)
        }
    }
}

impl<const BLOCK_SIZE: u64> Seek for BlockReader<BLOCK_SIZE> {
    fn seek(&mut self, block_index: SeekFrom) -> Result<u64> {
        self.inner.seek(match block_index {
            SeekFrom::Start(index) => SeekFrom::Start(
                index
                    .checked_mul(BLOCK_SIZE)
                    .ok_or_else(|| Error::new(ErrorKind::Other, "Integer overflow"))?,
            ),
            SeekFrom::End(index) => SeekFrom::End(
                index
                    .checked_mul(BLOCK_SIZE as i64)
                    .ok_or_else(|| Error::new(ErrorKind::Other, "Integer overflow"))?,
            ),
            SeekFrom::Current(index) => SeekFrom::Current(
                index
                    .checked_mul(BLOCK_SIZE as i64)
                    .ok_or_else(|| Error::new(ErrorKind::Other, "Integer overflow"))?,
            ),
        })
    }

    #[inline]
    fn rewind(&mut self) -> Result<()> {
        self.inner.rewind()
    }

    fn stream_position(&mut self) -> Result<u64> {
        let pos = self.inner.stream_position()?;
        if pos % BLOCK_SIZE != 0 {
            Err(Error::new(
                ErrorKind::Other,
                "Stream position is not a multiple of BLOCK_SIZE",
            ))
        } else {
            Ok(pos / BLOCK_SIZE)
        }
    }
}

impl<const BLOCK_SIZE: u64> BlockReader<BLOCK_SIZE> {
    /// Creates and returns a new reader object.
    pub fn new(path: &Path) -> Result<BlockReader<BLOCK_SIZE>> {
        if !path.is_file() {
            Err(Error::new(ErrorKind::Other, "Path is not a file."))
        } else if BLOCK_SIZE == 0 || BLOCK_SIZE > MAX_BLOCK_SIZE {
            Err(Error::new(
                ErrorKind::Other,
                "Block size must be 0 < BLOCK_SIZE < MAX_BLOCK_SIZE.",
            ))
        } else {
            let file: File = File::options().write(false).read(true).open(path)?;
            let file_size: u64 = file.metadata()?.len();
            if file_size == 0 {
                Err(Error::new(ErrorKind::Other, "File is empty."))
            } else if file_size % BLOCK_SIZE != 0 {
                Err(Error::new(
                    ErrorKind::Other,
                    "File size is not a multiple of BLOCK_SIZE.",
                ))
            } else {
                Ok(Self {
                    inner: BufReader::new(file),
                })
            }
        }
    }

    pub fn read_last_block(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.len() as u64 != BLOCK_SIZE {
            Err(Error::new(
                ErrorKind::Other,
                "Slice length is not equal to BLOCK_SIZE.",
            ))
        } else {
            self.inner.seek(SeekFrom::End(-(BLOCK_SIZE as i64)))?;
            self.inner.read_exact(buf).map_err(Error::from)
        }
    }
}

#[derive(Debug)]
pub struct BlockWriter<const BLOCK_SIZE: u64> {
    inner: BufWriter<File>,
}

impl<const BLOCK_SIZE: u64> BlockWriter<BLOCK_SIZE> {
    /// Creates and returns an new ```Writer```.
    pub fn new(path: &Path) -> Result<Self> {
        if !path.is_file() {
            Err(Error::new(ErrorKind::Other, "Path is not a file."))
        } else if BLOCK_SIZE == 0 || BLOCK_SIZE > MAX_BLOCK_SIZE {
            Err(Error::new(
                ErrorKind::Other,
                "Block size must be 0 < BLOCK_SIZE < MAX_BLOCK_SIZE.",
            ))
        } else {
            let file = if path.exists() {
                File::options().write(true).read(false).open(path)?
            } else {
                File::options()
                    .write(true)
                    .read(false)
                    .create_new(true)
                    .open(path)?
            };
            Ok(Self {
                inner: BufWriter::new(file),
            })
        }
    }
}

impl<const BLOCK_SIZE: u64> Write for BlockWriter<BLOCK_SIZE> {
    #[inline]
    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }

    /// Writes new blocks to the end of the stream.
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.len() as u64 % BLOCK_SIZE != 0 {
            Err(Error::new(
                ErrorKind::Other,
                "Slice length is not a multiple of BLOCK_SIZE",
            ))
        } else if self.inner.seek(SeekFrom::End(0))? % BLOCK_SIZE != 0 {
            Err(Error::new(
                ErrorKind::Other,
                "Stream position is not a multiple of BLOCK_SIZE",
            ))
        } else {
            self.inner.write_all(buf)?;
            self.inner.flush()?;
            Ok(buf.len() / BLOCK_SIZE as usize)
        }
    }
}
