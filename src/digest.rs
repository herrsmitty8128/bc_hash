// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

use crate::error::Error;
use std::cmp::Ordering;
use std::fmt::Display;
use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Digest<const S: usize>(pub [u8; S]);

impl<const S: usize> Default for Digest<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const S: usize> PartialEq<Self> for Digest<S> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<const S: usize> PartialEq<[u8; S]> for Digest<S> {
    fn eq(&self, other: &[u8; S]) -> bool {
        self.0 == *other
    }
}

impl<const S: usize> Eq for Digest<S> {}

impl<const S: usize> Display for Digest<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut data: String = String::new();
        for n in self.0 {
            data.push_str(&format!("{:02x}", n));
        }
        f.write_str(&data)
    }
}

impl<const S: usize> Deref for Digest<S> {
    type Target = [u8; S];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const S: usize> DerefMut for Digest<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const S: usize> AsRef<[u8; S]> for Digest<S> {
    fn as_ref(&self) -> &[u8; S] {
        &self.0
    }
}

impl<const S: usize> AsMut<[u8; S]> for Digest<S> {
    fn as_mut(&mut self) -> &mut [u8; S] {
        &mut self.0
    }
}

impl<const S: usize> Index<usize> for Digest<S> {
    type Output = u8;
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<const S: usize> IndexMut<usize> for Digest<S> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<const S: usize> FromStr for Digest<S> {
    type Err = Error;
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
            Ordering::Greater => Err(Error::StringTooLong),
            Ordering::Less => Err(Error::StringTooShort),
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

    pub fn from_bytes(bytes: &mut [u8]) -> std::result::Result<Digest<S>, Error> {
        match bytes.len().cmp(&S) {
            Ordering::Greater => Err(Error::SliceTooLong),
            Ordering::Less => Err(Error::SliceTooShort),
            Ordering::Equal => {
                let mut digest: Digest<S> = Digest::new();
                digest.0.clone_from_slice(bytes);
                Ok(digest)
            }
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}
