#[cfg(test)]
pub mod test {

    use bc_hash::OneWayHasher;
    use sha2::Digest;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake128, Shake256,
    };
    use std::{error::Error, io::Read};

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

    #[test]
    fn hash_testing() -> Result<(), Box<dyn Error>> {
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

        Ok(())
    }
}
