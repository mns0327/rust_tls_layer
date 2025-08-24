use crate::hash;
use crate::rand::rand_len;
use crate::bigint::BigInt;
use types::block_cipher;

pub trait RSA {
    fn encrypt(&self, n: &Vec<u8>, e: &Vec<u8>) -> Vec<u8>;
    fn pad(&self, k: usize) -> Vec<u8>;
    // fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8>;
}

impl RSA for Vec<u8> {
    fn encrypt(&self, n: &Vec<u8>, e: &Vec<u8>) -> Vec<u8> {
        let k = n.len();

        let padded = self.pad(k);

        let n = BigInt::new(n.to_vec());
        let e = BigInt::new(e.to_vec());
        let padded = BigInt::new(padded);

        let encrypted = padded.mod_pow(&e, &n);

        encrypted.value.to_vec()
    }
    
    fn pad(&self, k: usize) -> Vec<u8> {
        let ps_length = k - 3 - self.len();
        let mut ps: Vec<u8> = Vec::new();
        
        while ps.len() < ps_length {
            let r = rand_len(1)[0];
            if r != 0 {
                ps.push(r);
            }
        }

        let mut padded: Vec<u8> = Vec::new();
        padded.extend(vec![0x00, 0x02]);
        padded.extend(ps);
        padded.extend(vec![0x00]);
        padded.extend(self);
        padded
    }
}

pub fn prf(secret: Vec<u8>, label: Vec<u8>, seed: Vec<u8>, length: usize, hash_len: usize) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    let mut _seed = label.clone();
    _seed.extend(&seed);
    let mut tmp = hash::hmac_sha2(&secret, &_seed, hash_len);

    while result.len() < length {
        let mut new_seed = tmp.clone();
        new_seed.extend(&label);
        new_seed.extend(&seed);
        result.extend(hash::hmac_sha2(&secret, &new_seed, hash_len));
        tmp = hash::hmac_sha2(&secret, &tmp, hash_len);
    }
    
    result[0..length].to_vec()
}