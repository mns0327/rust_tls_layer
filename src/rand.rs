use crate::hash::{hmac_sha256, sha256};
use std::fs::File;
use std::io::Read;

pub fn rand() -> [u8; 32] {
    let mut file = File::open("/dev/random").unwrap();
    let mut buffer = vec![0u8; 32];
    file.read_exact(&mut buffer).unwrap();

    let key = sha256(&mut buffer);
    let random_bytes = hmac_sha256(key, buffer);

    random_bytes.try_into().unwrap()
}
