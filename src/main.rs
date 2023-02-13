use sha2::sha256::Digest;
use std::error::Error;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    let path: &Path = Path::new("./src/lib.rs");
    let digest: Digest = Digest::try_from(path)?;
    digest.print();

    let hex_string = digest.to_string();
    println!("\n{}", hex_string);

    let mut digest2: Digest = Digest::try_from(hex_string.as_str())?;
    let hex_string2: String = digest2.to_string();
    println!("{}", hex_string2);
    println!("{:?}", digest2);

    let bytes = digest2.as_bytes()?;
    let digest3: Digest = Digest::from_bytes(bytes)?;
    digest3.print();

    println!();

    Ok(())
}
