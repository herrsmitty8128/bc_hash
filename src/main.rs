// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

use bc_hash::{
    io::BlockStream,
    OneWayHasher,
};
use sha2::Digest;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};
use std::{
    error::Error,
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::Path,
};

macro_rules! cmp_fixed_len_digests {
    ($bc_type:ty, $other_type:ty, $mdlen:literal, $data:ident, $msg:literal) => {
        let mut digest: bc_hash::digest::Digest<$mdlen> = bc_hash::digest::Digest::new();
        let mut ctx = <$bc_type>::init();
        let a = {
            ctx.update(&$data[..]);
            ctx.finish(&mut digest.0);
            digest.0
        };
        let b = {
            let mut ctx2: $other_type = <$other_type>::new();
            sha2::Digest::update(&mut ctx2, &$data[..]);
            let mut digest: [u8; $mdlen] = [0; $mdlen];
            digest.clone_from_slice(ctx2.finalize().as_slice());
            digest
        };
        assert!(a == b, "{}", $msg);
        let c = {
            ctx.reset();
            ctx.update(&$data[..]);
            ctx.finish(&mut digest.0);
            digest.0
        };
        assert!(a == c, "Reset failed for {:?}", digest);
    };
}

macro_rules! cmp_variable_len_digests {
    ($bc_type:ty, $other_type:ty, $mdlen:literal, $data:ident, $msg:literal) => {
        let mut digest: bc_hash::digest::Digest<$mdlen> = bc_hash::digest::Digest::new();
        let mut ctx = <$bc_type>::init();
        let a = {
            ctx.update(&$data[..]);
            ctx.finish(&mut digest.0);
            digest.0
        };
        let b = {
            let mut hasher = <$other_type>::default();
            hasher.update(&$data);
            let mut reader = hasher.finalize_xof();
            let mut res1 = [0u8; $mdlen];
            XofReader::read(&mut reader, &mut res1);
            res1
        };
        assert!(a == b, "{}", $msg);
        let c = {
            ctx.reset();
            ctx.update(&$data[..]);
            ctx.finish(&mut digest.0);
            digest.0
        };
        assert!(a == c, "Reset failed for {:?}", digest);
    };
}

fn main() -> Result<(), Box<dyn Error>> {
    // load some data

    let mut data: Vec<u8> = Vec::new();
    let mut f = std::fs::File::open("./src/lib.rs")?;
    f.read_to_end(&mut data)?;

    // compare fixed length digest values

    cmp_fixed_len_digests!(
        bc_hash::sha2::Sha224,
        sha2::Sha224,
        28,
        data,
        "Sha224 failed"
    );
    cmp_fixed_len_digests!(
        bc_hash::sha2::Sha256,
        sha2::Sha256,
        32,
        data,
        "Sha256 failed"
    );
    cmp_fixed_len_digests!(
        bc_hash::sha2::Sha384,
        sha2::Sha384,
        48,
        data,
        "Sha384 failed"
    );
    cmp_fixed_len_digests!(
        bc_hash::sha2::Sha512,
        sha2::Sha512,
        64,
        data,
        "Sha512 failed"
    );
    cmp_fixed_len_digests!(
        bc_hash::sha2::Sha512_224,
        sha2::Sha512_224,
        28,
        data,
        "Sha512_224 failed"
    );
    cmp_fixed_len_digests!(
        bc_hash::sha2::Sha512_256,
        sha2::Sha512_256,
        32,
        data,
        "Sha512_256 failed"
    );

    cmp_fixed_len_digests!(
        bc_hash::sha3::Sha3_224,
        sha3::Sha3_224,
        28,
        data,
        "Sha3_224 failed"
    );
    cmp_fixed_len_digests!(
        bc_hash::sha3::Sha3_256,
        sha3::Sha3_256,
        32,
        data,
        "Sha3_256 failed"
    );
    cmp_fixed_len_digests!(
        bc_hash::sha3::Sha3_384,
        sha3::Sha3_384,
        48,
        data,
        "Sha3_384 failed"
    );
    cmp_fixed_len_digests!(
        bc_hash::sha3::Sha3_512,
        sha3::Sha3_512,
        64,
        data,
        "Sha3_512 failed"
    );

    // compare variable length digests

    cmp_variable_len_digests!(
        bc_hash::sha3::Shake128<64>,
        Shake128,
        64,
        data,
        "Shake128 failed"
    );
    cmp_variable_len_digests!(
        bc_hash::sha3::Shake256<64>,
        Shake256,
        64,
        data,
        "Shake256 failed"
    );

    // establish the file path and delete it if it already exists
    // test crate::io::BlockReader and crate::io::BlockWriter
    let path: &Path = Path::new("./test.blocks");
    
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let data: Vec<&str> = vec![
        "hello world",
        "thisxxxxxxx",
        "isxxxxxxxxx",
        "thexxxxxxxx",
        "testxxxxxxx",
        "dataxxxxxxx",
    ];
    let mut buf: [u8; 11] = [0; 11];
    let mut stream: BlockStream<11> = BlockStream::new(path)?;
    for d in &data {
        stream.write_all(d.as_bytes())?;
    }

    stream.rewind()?;

    let mut pos = 0;
    loop {
        match stream.read(&mut buf) {
            Ok(_) => {
                assert!(
                    String::from_utf8(Vec::from(buf))? == *data[pos as usize], //String::from(data[pos as usize]),
                    "reader.read() failed to read the correct data."
                );
            }
            Err(e) => {
                if e.kind() == ErrorKind::UnexpectedEof {
                    break;
                } else {
                    return Err(e)?;
                }
            }
        }
        pos += 1;
    }
    pos = stream.seek(SeekFrom::End(-2))?;
    assert!(
        pos == 4,
        "reader.seek() failed to return the correct position."
    );
    stream.read_exact(&mut buf)?;
    assert!(
        String::from_utf8(Vec::from(buf))? == *data[pos as usize], //String::from(data[pos as usize]),
        "reader.read() failed to read the correct data."
    );

    if path.exists() {
        std::fs::remove_file(path)?;
    }

    Ok(())
}
