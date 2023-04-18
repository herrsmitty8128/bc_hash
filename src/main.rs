use bc_hash::sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use bc_hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};
use bc_hash::{Digest, OneWayHash};
use std::error::Error;
use std::io::Read;

fn main() -> Result<(), Box<dyn Error>> {
    let mut data: Vec<u8> = Vec::new();
    let mut f = std::fs::File::open("./src/lib.rs")?;
    f.read_to_end(&mut data)?;

    //let mut s = String::from("Hello, world!");
    //let data = unsafe { s.as_bytes_mut() };

    let mut digest: Digest<28> = Digest::new();
    let mut ctx = Sha3_224::init();
    ctx.update(&data[..]);
    ctx.finish(&mut digest.0);
    println!("{}", &digest);

    let mut digest: Digest<32> = Digest::new();
    let mut ctx = Sha3_256::init();
    ctx.update(&data[..]);
    ctx.finish(&mut digest.0);
    println!("{}", &digest);

    let mut digest: Digest<48> = Digest::new();
    let mut ctx = Sha3_384::init();
    ctx.update(&data[..]);
    ctx.finish(&mut digest.0);
    println!("{}", &digest);

    let mut digest: Digest<64> = Digest::new();
    let mut ctx = Sha3_512::init();
    ctx.update(&data[..]);
    ctx.finish(&mut digest.0);
    println!("{}", &digest);

    let mut digest: Digest<28> = Digest::new();
    let mut ctx = Sha224::init();
    ctx.update(&data[..]);
    ctx.finish(&mut digest.0);
    println!("{}", &digest);

    let mut digest: Digest<32> = Digest::new();
    let mut ctx = Sha256::init();
    ctx.update(&data[..]);
    ctx.finish(&mut digest.0);
    println!("{}", &digest);

    let mut digest: Digest<48> = Digest::new();
    let mut ctx = Sha384::init();
    ctx.update(&data[..]);
    ctx.finish(&mut digest.0);
    println!("{}", &digest);

    let mut digest: Digest<64> = Digest::new();
    let mut ctx = Sha512::init();
    ctx.update(&data[..]);
    ctx.finish(&mut digest.0);
    println!("{}", &digest);

    let mut digest: Digest<28> = Digest::new();
    let mut ctx = Sha512_224::init();
    ctx.update(&data[..]);
    ctx.finish(&mut digest.0);
    println!("{}", &digest);

    let mut digest: Digest<32> = Digest::new();
    let mut ctx = Sha512_256::init();
    ctx.update(&data[..]);
    ctx.finish(&mut digest.0);
    println!("{}", &digest);

    let mut digest: Digest<44> = Digest::new();
    let mut ctx: Shake128<44> = Shake128::init();
    ctx.update(&data[..]);
    ctx.finish(&mut digest.0);
    println!("{}", &digest);

    let mut digest: Digest<44> = Digest::new();
    let mut ctx: Shake256<44> = Shake256::init();
    ctx.update(&data[..]);
    ctx.finish(&mut digest.0);
    println!("{}", &digest);

    Ok(())
}
