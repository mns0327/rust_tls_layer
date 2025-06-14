use core::panic;
use std::hash::Hash;

pub struct SHA2 {
    len: usize,
}

impl SHA2 {
    pub fn new(len: usize) -> Self {
        Self {len}
    }

    pub fn hash(self, msg: &Vec<u8>) -> Vec<u8> {
        let mut msg = msg.clone();
        let (mut h, block_size, output_size, rounds, word_bytes) = hash_info(self.len);
        let ml = msg.len() as u128 * 8;
        
        msg.push(0x80);
    
        let pad_len = if block_size == 64 { 8 } else { 16 };
        while (msg.len() + pad_len) % block_size != 0 {
            msg.push(0);
        }
        
        let ml_bytes = if block_size == 64 {
            (ml as u64).to_be_bytes().to_vec()
        } else {
            (ml as u128).to_be_bytes().to_vec()
        };
        msg.extend_from_slice(&ml_bytes);
        
        if word_bytes == 4 {
            self.core_u32(&h, &msg, output_size)
        } else {
            self.core_u64(&h, &msg, output_size)
        }
    }

    fn core_u64(self, h: &Vec<u64>, msg: &Vec<u8>, output_size: usize) -> Vec<u8> {
        let mut h = h.clone();
        fn to_words_64(b: &[u8]) -> Vec<u64> {
            b.chunks(8)
                .map(|chunk| {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(chunk);
                    u64::from_be_bytes(arr)
                })
                .collect()
        }
    
        for block in msg.chunks(128) {
            let mut w = to_words_64(block);
            w.resize(80, 0);
    
            for i in 16..80 {
                let s0 = w[i-15].rotate_right(1) ^ w[i-15].rotate_right(8) ^ (w[i-15] >> 7);
                let s1 = w[i-2].rotate_right(19) ^ w[i-2].rotate_right(61) ^ (w[i-2] >> 6);
                w[i] = w[i-16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i-7])
                    .wrapping_add(s1);
            }
    
            let mut a = h[0];
            let mut b = h[1];
            let mut c = h[2];
            let mut d = h[3];
            let mut e = h[4];
            let mut f = h[5];
            let mut g = h[6];
            let mut hh = h[7];
    
            for i in 0..80 {
                let s1 = rotr(e, 14, 8) ^ rotr(e, 18, 8) ^ rotr(e, 41, 8);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = hh.wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(SHA2_64_K[i])
                    .wrapping_add(w[i]);
                let s0 = rotr(a, 28, 8) ^ rotr(a, 34, 8) ^ rotr(a, 39, 8);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);
            
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }
    
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }

        let mut out = vec![];
        for &val in h.iter() {
            out.extend(&val.to_be_bytes());
        }
        out[..output_size].to_vec()
    }

    fn core_u32(self, h: &Vec<u64>, msg: &Vec<u8>, output_size: usize) -> Vec<u8> {
        let mut h = h.iter().map(|&val| val as u32).collect::<Vec<u32>>();
        
        for block in msg.chunks(64) {
            let mut w = [0u32; 64];
            for (i, word_bytes) in block.chunks(4).take(16).enumerate() {
                w[i] = u32::from_be_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
            }
            for i in 16..64 {
                let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
                let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
                w[i] = w[i-16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i-7])
                    .wrapping_add(s1);
            }
        
            let mut a = h[0];
            let mut b = h[1];
            let mut c = h[2];
            let mut d = h[3];
            let mut e = h[4];
            let mut f = h[5];
            let mut g = h[6];
            let mut h0 = h[7];
        
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h0.wrapping_add(s1).wrapping_add(ch)
                    .wrapping_add(SHA2_32_K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);
        
                h0 = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }
        
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(h0);
        }
        
        let mut out = vec![];
        for &val in h.iter() {
            out.extend(val.to_be_bytes());
        }
        out[..output_size].to_vec()
    }
}

fn hash_info(len: usize) -> (Vec<u64>, usize, usize, usize, usize) {
    let (h_init, block_size, output_size, rounds, word_bytes) = match len {
        224 => (
            vec![
                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
            ],
            64,
            28,
            64,
            4
        ),
        256 => (
            vec![
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            64,
            32,
            64,
            4
        ),
        384 => (
            vec![
                0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                0x9159015a3070dd17, 0x152fecd8f70e5939,
                0x67332667ffc00b31, 0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
            ],
            128,
            48,
            80,
            8
        ),
        512 => (
            vec![
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
            ],
            128,
            64,
            80,
            8
        ),
        _ => panic!("Unsupported sha2 lenght")
    };
    (h_init, block_size, output_size, rounds, word_bytes)
}

pub const SHA2_32_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];


pub const SHA2_64_K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

pub fn hmac_sha2(key: &Vec<u8>, msg: &Vec<u8>, len: usize) -> Vec<u8> {
    let block_size: usize = if len <= 256 { 64 } else { 128 };
    let mut key = key.clone();
    key.resize(block_size, 0);

    for _ in key.len()..block_size {
        key.push(0);
    }
    
    let mut o_key_pad: Vec<u8> = vec![];
    let mut i_key_pad: Vec<u8> = vec![];

    for i in 0..block_size {
        o_key_pad.push(key[i] ^ 0x5c);
        i_key_pad.push(key[i] ^ 0x36);
    }
    
    i_key_pad.extend(msg);
    let inner_hash = SHA2::new(len).hash(&i_key_pad);

    let mut hmac_msg = o_key_pad.clone();
    hmac_msg.extend(inner_hash);
    SHA2::new(len).hash(&mut hmac_msg)
}

pub trait VecStructU8 {
    fn to_u32_vec(&self) -> Vec<u32>;
    fn hex_display(&self) -> String;
}

impl VecStructU8 for Vec<u8> {
    fn to_u32_vec(&self) -> Vec<u32> {
        let mut result = Vec::new();
        for chunk in self.chunks(4) {
            let mut bytes = [0u8; 4];
            for (i, &byte) in chunk.iter().enumerate() {
                bytes[i] = byte;
            }
            result.push(u32::from_be_bytes(bytes));
        }
        result
    }

    fn hex_display(&self) -> String {
        self.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join("")
    }
}

trait VecStructU32 {
    fn to_u8_vec(&self) -> Vec<u8>;
}

impl VecStructU32 for Vec<u32> {
    fn to_u8_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();
        for &val in self {
            result.extend_from_slice(&val.to_be_bytes());
        }
        result
    }
}

fn rotr(x: u64, n: usize, w: usize) -> u64 {
    if w == 4 {
        ((x as u32).rotate_right(n as u32)) as u64
    } else {
        x.rotate_right(n as u32)
    }
}
