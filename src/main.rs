
use sha2::sha256::Digest;

fn main() {
    let path: String = String::from("./src/lib.rs");
    match Digest::from_file(&path) {
        Ok(digest) => {
            digest.print_as_hex();
            println!();
        }
        Err(e) => println!("{:?}", e),
    }
}
