const K: [u32; 64] = [
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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

pub fn sha256(msg: &mut Vec<u8>) -> Vec<u8> {
    let mut h: Vec<u32> = vec![
        0x6a09e667, 0xbb67ae85,
        0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19
    ];

    let ml = msg.len() * 8;
    
    msg.push(0x80);

    while (msg.len() * 8) % 512 != 448 {
        msg.push(0)
    }

    let lm_bytes: Vec<u8> = ml.to_be_bytes().to_vec();
    msg.extend(lm_bytes);

    // step 64
    for i in (0..msg.len()).step_by(64) {
        let mut w = msg[i..i+64].to_vec().to_u32_vec();
        w.extend(vec![0; 48]);

        for j in 16..64 {
            let s0 = w[j-15].rightrotate(7) ^ w[j-15].rightrotate(18) ^ (w[j-15] >> 3);
            let s1 = w[j-2].rightrotate(17) ^ w[j-2].rightrotate(19) ^ (w[j-2] >> 10);
            w[j] = ((w[j-16] as u64 + s0 as u64 + w[j-7] as u64 + s1 as u64) & 0xffffffff) as u32;
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h0 = h[7];

        for j in 0..64 {
            let s1 = e.rightrotate(6) ^ e.rightrotate(11) ^ e.rightrotate(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = ((h0 as u64 + s1 as u64 + ch as u64 + K[j] as u64 + w[j] as u64) & 0xffffffff) as u32;
            let s0 = a.rightrotate(2) ^ a.rightrotate(13) ^ a.rightrotate(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = ((s0 as u64 + maj as u64) & 0xffffffff) as u32;

            h0 = g;
            g = f;
            f = e;
            e = (d as u64 + temp1 as u64) as u32 & 0xffffffff;
            d = c;
            c = b;
            b = a;
            a = (temp1 as u64 + temp2 as u64) as u32 & 0xffffffff;
        }

        let mut new_h: Vec<u32> = h.iter()
            .zip([a, b, c, d, e, f, g, h0])
            .map(|(&x, y)| (x as u64 + y as u64) as u32 & 0xffffffff)
            .collect();
        
        h = new_h;
    }

    h.to_u8_vec()
}

pub fn hmac_sha256(key: Vec<u8>, msg: Vec<u8>) -> Vec<u8> {
    let block_size: usize = 64;
    let mut key = key;
    if key.len() > block_size {
        key = sha256(&mut key);
    }

    for i in key.len()..block_size {
        key.push(0);
    }
    
    let mut o_key_pad: Vec<u8> = vec![];
    let mut i_key_pad: Vec<u8> = vec![];

    for i in 0..block_size {
        o_key_pad.push(key[i] ^ 0x5c);
        i_key_pad.push(key[i] ^ 0x36);
    }
    
    i_key_pad.extend(msg);

    let tmp = sha256(&mut i_key_pad);
    let mut hmac_msg = o_key_pad.clone();
    hmac_msg.extend(tmp);

    sha256(&mut hmac_msg)
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

trait rotateU32 {
    fn rightrotate(&self, n: i16) -> u32;
}

impl rotateU32 for u32 {
    fn rightrotate(&self, n: i16) -> u32 {
        (self >> n) | (self << (32 - n)) & 0xffffffff
    }
}