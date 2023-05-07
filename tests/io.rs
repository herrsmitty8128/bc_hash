#[cfg(test)]
pub mod test {

    use bc_hash::io::BlockStream;
    use std::{
        error::Error,
        io::{ErrorKind, Read, Seek, SeekFrom, Write},
        path::Path,
    };

    #[test]
    pub fn io_test() -> Result<(), Box<dyn Error>> {
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
}
