/// MIT License
///
/// Copyright (c) 2022 herrsmitty8128
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///  
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
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
