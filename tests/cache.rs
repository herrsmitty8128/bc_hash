#[cfg(test)]
pub mod test {

    use bc_hash::cache::Cache;

    use std::{error::Error, thread::sleep, time::Duration};

    #[test]
    fn test_cache() -> Result<(), Box<dyn Error>> {
        // Test the cache

        let mut c: Cache<3> = Cache::new(4);
        let block: [u8; 3] = [0; 3];
        for block_num in 0..5 {
            c.put(block_num, &block);
            sleep(Duration::from_millis(100));
            println!("#####");
            for (num, b) in c.iter() {
                println!("{}: {:?}", num, b);
            }
        }

        Ok(())
    }
}
