pub mod block_cipher;

pub trait EncryptStruct {
    type Params;

    fn encrypt(&self, msg: Vec<u8>, params: &Self::Params) -> Vec<u8>;
}

pub trait DecryptStruct {
    type Params;

    fn decrypt(&self, msg: Vec<u8>, params: &Self::Params) -> Vec<u8>;
}

pub trait Padding {
    fn pad(&self, value: Vec<u8>) -> Vec<u8>;
    fn unpad(&self, value: Vec<u8>) -> Vec<u8>;    
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