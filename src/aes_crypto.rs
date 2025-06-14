use std::{char::EscapeUnicode, sync::Arc};
use crate::block_cipher;
use crate::hash::VecStructU8;

pub const S_BOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

pub const INV_S_BOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

pub const RCON: [u8; 10] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
];

fn get_aes_params(key_len: usize) -> (usize, usize, usize) {
    match key_len {
        16 => (4, 10, 44),
        24 => (6, 12, 52),
        32 => (8, 14, 60),
        _ => panic!("AES key length not supported"),
    }
}

fn sub_bytes(state: [u8; 16]) -> [u8; 16] {
    state.iter().map(|&b| S_BOX[b as usize]).collect::<Vec<u8>>().try_into().unwrap()
}

fn shift_rows(state: [u8; 16]) -> [u8; 16] {
    vec![
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11],
    ].try_into().unwrap()
}

fn xtime(a: u8) -> u8 {
    if a & 0x80 != 0 {
        ((a << 1) ^ 0x1b) & 0xff
    } else {
        a << 1
    }
}

fn mix_columns(state: [u8; 16]) -> [u8; 16] {
    let mut result: Vec<u8> = Vec::new();
    for i in (0..16).step_by(4) {
        let col = state[i..i+4].to_vec();
        result.extend(
            vec![
                xtime(col[0]) ^ xtime(col[1]) ^ col[1] ^ col[2] ^ col[3],
                col[0] ^ xtime(col[1]) ^ xtime(col[2]) ^ col[2] ^ col[3],
                col[0] ^ col[1] ^ xtime(col[2]) ^ xtime(col[3]) ^ col[3],
                xtime(col[0]) ^ col[0] ^ col[1] ^ col[2] ^ xtime(col[3]),
            ]);
    }
    result.try_into().unwrap()
}

fn add_round_key(state: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    state.iter().zip(key.iter()).map(|(s, k)| s ^ k).collect::<Vec<u8>>().try_into().unwrap()
}

fn key_expansion(key: &[u8]) -> Vec<u8> {
    let (nk, nr, nwords) = get_aes_params(key.len());
    let mut key_columns: Vec<Vec<u8>> = (0..nk)
        .map(|i| key[i*4..(i+1)*4].to_vec())
        .collect();

    let mut rcon_i = 0;
    while key_columns.len() < nwords {
        let mut word = key_columns[key_columns.len() - 1].to_vec();
        if key_columns.len() % nk == 0 {
            word = (0..4).map(|j| S_BOX[word[(j + 1) % 4] as usize])
                .collect::<Vec<u8>>();
            word[0] ^= RCON[rcon_i];
            rcon_i += 1;
        } else if nk > 6 && (key_columns.len() % nk == 4) {
            word = word.iter().map(|&b| S_BOX[b as usize]).collect();
        }
        let prev_word = key_columns[key_columns.len() - nk].clone();
        word = word.iter().zip(prev_word.iter()).map(|(a, b)| a ^ b).collect();
        key_columns.push(word);
    }

    key_columns.iter().flatten().cloned().collect()
}

pub fn aes_encrypt_block(plaintext: [u8; 16], key: &[u8]) -> [u8; 16] {
    let (_, nr, _) = get_aes_params(key.len());
    let expanded_key = key_expansion(key);

    let mut state = plaintext;

    state = add_round_key(state, expanded_key[0..16].try_into().unwrap());
    for round in 1..nr {
        state = sub_bytes(state);
        state = shift_rows(state);
        state = mix_columns(state);
        state = add_round_key(state, expanded_key[round*16..(round+1)*16].try_into().unwrap());
    }
    state = sub_bytes(state);
    state = shift_rows(state);
    state = add_round_key(state, expanded_key[nr*16..(nr+1)*16].try_into().unwrap());

    state
}

pub fn inv_shift_rows(state: [u8; 16]) -> [u8; 16] {
    vec![
        state[0], state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3],
    ].try_into().unwrap()
}

fn mult(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut result = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }

        let high_bit = a & 0x80;
        a = (a << 1) & 0xff;
        if high_bit != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

pub fn inv_mix_columns(state: [u8; 16]) -> [u8; 16] {
    let mut result: Vec<u8> = Vec::new();
    for i in (0..16).step_by(4) {
        let col = state[i..i+4].to_vec();
        result.extend(
        vec![
            mult(col[0], 0x0e) ^ mult(col[1], 0x0b) ^ mult(col[2], 0x0d) ^ mult(col[3], 0x09),
            mult(col[0], 0x09) ^ mult(col[1], 0x0e) ^ mult(col[2], 0x0b) ^ mult(col[3], 0x0d),
            mult(col[0], 0x0d) ^ mult(col[1], 0x09) ^ mult(col[2], 0x0e) ^ mult(col[3], 0x0b),
            mult(col[0], 0x0b) ^ mult(col[1], 0x0d) ^ mult(col[2], 0x09) ^ mult(col[3], 0x0e),
        ]);
    }
    result.try_into().unwrap()
}

pub fn aes_decrypt_block(plaintext: [u8; 16], key: &[u8]) -> [u8; 16] {
    let mut state: [u8; 16] = plaintext.clone();
    let expanded_key: Vec<u8> = key_expansion(key);

    state = add_round_key(state, expanded_key[160..176].try_into().unwrap());
    
    for round in (1..10).rev() {
        state = inv_shift_rows(state).try_into().unwrap();
        state = state.iter().map(|&b| INV_S_BOX[b as usize]).collect::<Vec<u8>>().try_into().unwrap();
        state = add_round_key(state, expanded_key[round*16..(round+1)*16].try_into().unwrap());
        state = inv_mix_columns(state).try_into().unwrap();
    }
    state = inv_shift_rows(state).try_into().unwrap();
    state = state.iter().map(|&b| INV_S_BOX[b as usize]).collect::<Vec<u8>>().try_into().unwrap();
    state = add_round_key(state,expanded_key[0..16].try_into().unwrap());
    state
}

pub struct AES {
    key: Vec<u8>,
    // iv
    block_mode: fn(fn([u8; 16], &[u8]) -> [u8; 16], Vec<u8>, Vec<u8>, Vec<u8>, bool) -> Vec<u8>
}

impl AES {
    pub fn new(key: Vec<u8>, block_mode: fn(fn([u8; 16], &[u8]) -> [u8; 16], Vec<u8>, Vec<u8>, Vec<u8>, bool) -> Vec<u8>) -> Self {
        Self { key, block_mode }
    }

    pub fn encrypt(&self, plaintext: Vec<u8>) -> Vec<u8> {
        (self.block_mode)(aes_encrypt_block, plaintext, self.key.clone(), b"".to_vec(), true)
    }

    pub fn decrypt(&self, plaintext: Vec<u8>) -> Vec<u8> {
        (self.block_mode)(aes_decrypt_block, plaintext, self.key.clone(), b"".to_vec(), false)
    }
}

fn gf_mul(x: u128, y: u128) -> u128 {
    let mut x = x.clone();
    let r: u128 = 0xe1000000000000000000000000000000;
    let mut z = 0;
    for i in 0..128 {
        if y & (1 << (127 - i)) != 0 {
            z ^= x;
        }
        if x & 1 == 1 {
            x = (x >> 1) ^ r;
        } else {
            x >>= 1;
        }
    }
    z
}

fn inc32(counter: &Vec<u8>) -> Vec<u8> {
    let mut value = u32::from_be_bytes(counter[counter.len() - 4..].try_into().unwrap());
    value += 1;
    let mut result = counter.clone();
    result[counter.len() - 4..].copy_from_slice(&u32::to_be_bytes(value));
    result
}

fn pad16(data: Vec<u8>) -> Vec<u8> {
    if data.len() % 16 == 0 {
        return data;
    }
    let mut result = data.clone();
    result.extend(vec![0; 16 - data.len() % 16]);
    result
}

fn process_block(y: &mut u128, h: &u128, data: Vec<u8>) {
    for i in (0..data.len()).step_by(16) {
        *y = gf_mul(*y ^ u128::from_be_bytes(data[i..i+16].try_into().unwrap()), h.clone())
    }
}

fn ghash(h: Vec<u8>, a: Vec<u8>, c: Vec<u8>) -> Vec<u8> {
    let h = u128::from_be_bytes(h.try_into().unwrap());
    let mut y: u128 = 0;

    process_block(&mut y, &h, pad16(a.clone()));
    process_block(&mut y, &h, pad16(c.clone()));

    let mut length_block: Vec<u8> = u64::to_be_bytes(a.len() as u64 * 8).to_vec();
    length_block.extend(u64::to_be_bytes(c.len() as u64 * 8).to_vec());
    y = gf_mul(y ^ u128::from_be_bytes(length_block.try_into().unwrap()), h.clone());

    u128::to_be_bytes(y).to_vec()
}

pub struct AES_GCM {
    key: Vec<u8>,
}

impl AES_GCM {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
    
    pub fn encrypt(&self, iv: Vec<u8>, pt: Vec<u8>, aad: Vec<u8>) -> Vec<u8> {
        let mut aes = AES::new(self.key.clone(), block_cipher::ECB_MODE);
        let H = aes.encrypt([0; 16].to_vec());
        let mut J0 = iv.clone();
        J0.extend([0, 0, 0, 1]);

        let mut ctr = inc32(&J0);
        let mut ciphertext = vec![];
        for i in (0..pt.len() as i64).step_by(16) {
            let mut block = vec![];
            if i + 16 > pt.len() as i64 {
                block = pt[i as usize..].to_vec();
            } else {
                block = pt[i as usize..i as usize + 16].to_vec();
            }
            let keystream = aes.encrypt(ctr.clone());
            ctr = inc32(&ctr);
            ciphertext.extend(block.iter().zip(keystream[..16].iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>());
        }

        let S = ghash(H, aad.clone(), ciphertext.clone());
        let tag = aes.encrypt(J0.clone()).iter().zip(S.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>();
        ciphertext.extend(tag);
        ciphertext
    }

    pub fn decrypt(&self, iv: Vec<u8>, ciphertext_with_tag: Vec<u8>, aad: Vec<u8>) -> Vec<u8> {
        let aes = AES::new(self.key.clone(), block_cipher::ECB_MODE);
        let h: Vec<u8> = aes.encrypt([0; 16].to_vec());
        let mut J0 = iv.clone();
        J0.extend([0, 0, 0, 1]);
    
        let tag = ciphertext_with_tag[ciphertext_with_tag.len() - 16..].to_vec();
        let ciphertext = ciphertext_with_tag[..ciphertext_with_tag.len() - 16].to_vec();
    
        let mut ctr = inc32(&J0);
        let mut plaintext = vec![];
        for i in (0..ciphertext.len() as i64).step_by(16) {
            let keystream = aes.encrypt(ctr.clone());
            ctr = inc32(&ctr);
            if i + 16 > ciphertext.len() as i64 {
                plaintext.extend(ciphertext[i as usize..].to_vec().iter().zip(keystream[..16].iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>());
            } else {
                plaintext.extend(ciphertext[i as usize..i as usize + 16].iter().zip(keystream[..16].iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>());
            }
        }
        
        let S = ghash(h, aad.clone(), ciphertext.clone());
        let computed_tag = aes.encrypt(J0.clone()).iter().zip(S.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>();
    
        if computed_tag != tag {
            panic!("Authentication failed: GCM tag mismatch");
        }
    
        plaintext
    }
}