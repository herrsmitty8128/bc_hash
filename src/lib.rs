// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.
pub mod digest;
pub mod error;
pub mod merkle;
pub mod sha2;
pub mod sha3;

pub trait OneWayHash<const MDLEN: usize>: std::io::Write
where
    Self: Sized,
{
    fn init() -> Self;
    fn reset(&mut self);
    fn update(&mut self, data: &[u8]) -> &mut Self;
    fn finish(&mut self, digest: &mut [u8; MDLEN]);
}

pub trait FinishXOF
where
    Self: Sized,
{
    fn finish_xof(&mut self, digest: &mut [u8]);
}
