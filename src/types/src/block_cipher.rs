pub fn ECB_MODE(cipher_func: fn([u8; 16], &[u8]) -> [u8; 16], data: Vec<u8>, key: Vec<u8>, iv: Vec<u8>, mode: bool) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    let bytes_data: Vec<u8>;
    if mode {
        bytes_data = pad(data, 16);
    } else {
        bytes_data = data.clone();
    }
    for i in (0..bytes_data.len()).step_by(16) {
        result.extend(cipher_func(bytes_data[i..i+16].try_into().unwrap(), &key));
    }
    if !mode {
        result = unpad(result)
    }
    result
}

pub fn pad(data: Vec<u8>, block_size: usize) -> Vec<u8> {
    if data.len() % block_size == 0 {
        return data;
    }
    let mut pad_len = block_size - data.len() % block_size;
    let mut result = data.clone();
    result.extend(vec![pad_len as u8; pad_len]);
    result
}

pub fn unpad(data: Vec<u8>) -> Vec<u8> {
    let pad_len = data[data.len() - 1] as usize;
    data[..data.len() - pad_len].to_vec()
}