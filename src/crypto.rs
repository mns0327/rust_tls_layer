use crate::hash::VecStructU8;
use crate::rand::rand_len;
use crate::bigint::BigInt;

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
        let padded = BigInt::new(padded);;

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

