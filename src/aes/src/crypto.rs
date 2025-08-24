use types::{
    EncryptStruct,
    DecryptStruct,
    block_cipher
};
use crate::core;

pub struct AesGcmParams {
    pub iv: Vec<u8>,
    pub aad: Vec<u8>,
}

pub struct AesGcm {
    key: Vec<u8>,
}

impl AesGcm {
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key
        }
    }
}

impl EncryptStruct for AesGcm {
    type Params = AesGcmParams;

    fn encrypt(&self, msg: Vec<u8>, params: &Self::Params) -> Vec<u8> {
        let mut aes = core::AES::new(self.key.clone(), block_cipher::ECB_MODE);
        let H = aes.encrypt([0; 16].to_vec());
        let mut J0 = params.iv.clone();
        J0.extend([0, 0, 0, 1]);

        let mut ctr = core::inc32(&J0);
        let mut ciphertext = vec![];
        for i in (0..msg.len() as i64).step_by(16) {
            let mut block = vec![];
            if i + 16 > msg.len() as i64 {
                block = msg[i as usize..].to_vec();
            } else {
                block = msg[i as usize..i as usize + 16].to_vec();
            }
            let keystream = aes.encrypt(ctr.clone());
            ctr = core::inc32(&ctr);
            ciphertext.extend(block.iter().zip(keystream[..16].iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>());
        }

        let S = core::ghash(H, params.aad.clone(), ciphertext.clone());
        let tag = aes.encrypt(J0.clone()).iter().zip(S.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>();
        ciphertext.extend(tag);
        ciphertext
    }
}

impl DecryptStruct for AesGcm {
    type Params = AesGcmParams;

    fn decrypt(&self, msg: Vec<u8>, params: &Self::Params) -> Vec<u8> {
        let aes = core::AES::new(self.key.clone(), block_cipher::ECB_MODE);
        let h: Vec<u8> = aes.encrypt([0; 16].to_vec());
        let mut J0 = params.iv.clone();
        J0.extend([0, 0, 0, 1]);
    
        let tag = msg[msg.len() - 16..].to_vec();
        let ciphertext = msg[..msg.len() - 16].to_vec();
    
        let mut ctr = core::inc32(&J0);
        let mut plaintext = vec![];
        for i in (0..ciphertext.len() as i64).step_by(16) {
            let keystream = aes.encrypt(ctr.clone());
            ctr = core::inc32(&ctr);
            if i + 16 > ciphertext.len() as i64 {
                plaintext.extend(ciphertext[i as usize..].to_vec().iter().zip(keystream[..16].iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>());
            } else {
                plaintext.extend(ciphertext[i as usize..i as usize + 16].iter().zip(keystream[..16].iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>());
            }
        }
        
        let S = core::ghash(h, params.aad.clone(), ciphertext.clone());
        let computed_tag = aes.encrypt(J0.clone()).iter().zip(S.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>();
    
        if computed_tag != tag {
            panic!("Authentication failed: GCM tag mismatch");
        }
    
        plaintext
    }
}

