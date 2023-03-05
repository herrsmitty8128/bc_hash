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
    digest.serialize(&mut bytes)?;
    digest.deserialize_in_place(&bytes)?;
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
