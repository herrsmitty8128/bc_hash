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
use bc_hash::crypto::Digest as CryptoDigest;
use bc_hash::sha256::Digest;
use std::error::Error;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    let path: &Path = Path::new("./src/lib.rs");
    println!("{:?}", path.as_os_str());
    let digest: Digest = Digest::try_from(path)?;
    println!("{}", digest);

    let hex_string = digest.to_string();
    println!("{}", hex_string);

    let mut digest: Digest = Digest::try_from(hex_string.as_str())?;
    let hex_string: String = digest.to_string();
    println!("{}", hex_string);

    let mut bytes: [u8; 32] = [0; 32];
    digest.serialize_to(&mut bytes)?;
    digest.deserialize_from(&bytes)?;
    println!("{} after byte conversion", digest);

    let mut arr: Vec<u8> = vec![6, 4, 8, 2, 3, 0, 2];
    println!("Vec.len() = {}", arr.len());
    println!("{:?}", arr);
    let digest: Digest = Digest::from(&mut arr);
    println!("{}", digest);
    println!("Vec.len() = {}", arr.len());
    println!("{:?}", arr);

    println!();

    Ok(())
}
