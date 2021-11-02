mod socket;

use crate::socket::{Algorithm, Context};
use std::io;
use std::io::{Read, Write};

const SHA224: Algorithm = Algorithm::new(b"hash", b"sha224");

const SHA256: Algorithm = Algorithm::new(b"hash", b"sha256");

const SHA384: Algorithm = Algorithm::new(b"hash", b"sha384");

const SHA512: Algorithm = Algorithm::new(b"hash", b"sha512");

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
