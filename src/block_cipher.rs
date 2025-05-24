pub fn ECB_MODE_ENCRYPT(cipher_func: fn([u8; 16], [u8; 16]) -> [u8; 16], data: Vec<u8>, key: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    let mut result = Vec::new();
    let padded_data = pad(data, 16);
    for i in (0..padded_data.len()).step_by(16) {
        result.extend(cipher_func(padded_data[i..i+16].try_into().unwrap(), key.clone().try_into().unwrap()));
    }
    result
}

pub fn ECB_MODE_DECRYPT(cipher_func: fn([u8; 16], [u8; 16]) -> [u8; 16], data: Vec<u8>, key: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    let mut result = Vec::new();
    for i in (0..data.len()).step_by(16) {
        result.extend(cipher_func(data[i..i+16].try_into().unwrap(), key.clone().try_into().unwrap()));
    }
    unpad(result)
}

fn pad(data: Vec<u8>, block_size: usize) -> Vec<u8> {
    let mut pad_len = block_size - data.len() % block_size;
    let mut result = data.clone();
    result.extend(vec![pad_len as u8; pad_len]);
    result
}

fn unpad(data: Vec<u8>) -> Vec<u8> {
    let pad_len = data[data.len() - 1] as usize;
    data[..data.len() - pad_len].to_vec()
}