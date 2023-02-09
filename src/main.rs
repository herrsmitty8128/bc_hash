use sha2::sha256::Digest;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let path: String = String::from("./src/lib.rs");
    let digest: Digest = Digest::from_file(&path)?;
    digest.print_as_hex();

    let hex_string = digest.to_hex_string();
    println!("\n{}", hex_string);

    let mut digest2: Digest = Digest::from_hex_string(hex_string.as_str())?;
    let hex_string2: String = digest2.to_hex_string();
    println!("{}", hex_string2);

    let bytes = digest2.as_bytes()?;
    let digest3: Digest = Digest::new(bytes)?;
    digest3.print_as_hex();

    println!();

    Ok(())
}
