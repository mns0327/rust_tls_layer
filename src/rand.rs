use crate::hash;
use std::fs::File;
use std::io::Read;

pub fn rand() -> [u8; 32] {
    let mut file = File::open("/dev/random").unwrap();
    let mut buffer = vec![0u8; 32];
    file.read_exact(&mut buffer).unwrap();

    let key = hash::SHA2::new(256).hash(&mut buffer);
    let random_bytes = hash::hmac_sha2(&key, &buffer, 256);

    random_bytes.try_into().unwrap()
}

pub fn rand_len(len: usize) -> Vec<u8> {
    let mut rng: Vec<u8> = Vec::new();
    while rng.len() < len {
        rng.extend(rand());
    }

    rng[0..len].to_vec()
}