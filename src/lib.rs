mod socket;

use crate::socket::{Algorithm, Context, Operation};
use std::io;
use std::io::{Read, Write};

pub struct DrbgNoprSha256 {
    #[cfg_attr(not(feature = "rand"), allow(dead_code))]
    operation: Operation,
}

const SHA224: Algorithm = Algorithm::new(b"hash", b"sha224");

const SHA256: Algorithm = Algorithm::new(b"hash", b"sha256");

const SHA384: Algorithm = Algorithm::new(b"hash", b"sha384");

const SHA512: Algorithm = Algorithm::new(b"hash", b"sha512");

const DRBG_NOPR_SHA256: Algorithm = Algorithm::new(b"rng", b"drbg_nopr_sha256");

impl DrbgNoprSha256 {
    pub fn new(seed: &[u8]) -> io::Result<DrbgNoprSha256> {
        let mut context = Context::new(&DRBG_NOPR_SHA256)?;
        // TODO: Documentation states it's not necessary for DRBGs, but I get an EINVAL?
        context.set_key(seed)?;
        Ok(DrbgNoprSha256 {
            operation: context.start()?,
        })
    }
}

#[cfg(feature = "rand")]
impl rand_core::RngCore for DrbgNoprSha256 {
    fn next_u32(&mut self) -> u32 {
        let mut raw = [0; 4];
        self.operation.read_exact(&mut raw).unwrap();
        u32::from_ne_bytes(raw)
    }

    fn next_u64(&mut self) -> u64 {
        let mut raw = [0; 8];
        self.operation.read_exact(&mut raw).unwrap();
        u64::from_ne_bytes(raw)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.operation.read_exact(dest).unwrap();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.operation
            .read_exact(dest)
            .map_err(rand_core::Error::new)
    }
}

pub fn sha224(data: &[u8]) -> io::Result<[u8; 28]> {
    hash(data, &SHA224)
}

pub fn sha256(data: &[u8]) -> io::Result<[u8; 32]> {
    hash(data, &SHA256)
}

pub fn sha384(data: &[u8]) -> io::Result<[u8; 48]> {
    hash(data, &SHA384)
}

pub fn sha512(data: &[u8]) -> io::Result<[u8; 64]> {
    hash(data, &SHA512)
}

fn hash<const N: usize>(data: &[u8], algorithm: &Algorithm) -> io::Result<[u8; N]> {
    let context = Context::new(algorithm)?;
    let mut operation = context.start()?;
    operation.write_all(data)?;
    let mut hash = [0; N];
    operation.read_exact(&mut hash)?;
    Ok(hash)
}

#[test]
fn compare_sha224() {
    compare::<sha2::Sha224, 28>(sha224);
}

#[test]
fn compare_sha256() {
    compare::<sha2::Sha256, 32>(sha256);
}

#[test]
fn compare_sha384() {
    compare::<sha2::Sha384, 48>(sha384);
}

#[test]
fn compare_sha512() {
    compare::<sha2::Sha512, 64>(sha512);
}

#[cfg(test)]
fn compare<T: sha2::Digest, const N: usize>(kernel: fn(&[u8]) -> io::Result<[u8; N]>) {
    let data = "Hello, world!".as_bytes();
    assert_eq!(kernel(data).unwrap(), T::digest(data).as_slice());
}

#[cfg(feature = "rand")]
#[test]
fn succeeds_drbg_nopr_sha256() {
    use rand_core::RngCore;
    // TODO: This turns out to be nondeterministic for some reason?
    let mut rng = DrbgNoprSha256::new(include_bytes!("lib.rs")).unwrap();
    let mut examples = [0; 4];
    rng.fill_bytes(&mut examples);
    println!("{:?}", examples);
}
