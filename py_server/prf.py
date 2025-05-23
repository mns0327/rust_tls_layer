import hmac, hashlib

def prf(secret, label, seed, size):
    def P_hash(secret, seed):
        result = b''
        A = hmac.new(secret, seed, hashlib.sha256).digest()
        while len(result) < size:
            result += hmac.new(secret, A + seed, hashlib.sha256).digest()
            A = hmac.new(secret, A, hashlib.sha256).digest()
        return result[:size]

    return P_hash(secret, label + seed)

# 예시 입력들
premaster_secret = b'\x03\x03' + b'\x11' * 46
client_random = b'\xaa' * 32
server_random = b'\xbb' * 32

# Step 1: master_secret
master_secret = prf(premaster_secret, b"master secret", client_random + server_random, 48)

# Step 2: key_block
key_block_len = 20 + 20 + 16 + 16 + 16 + 16  # mac + key + iv × 2
key_block = prf(master_secret, b"key expansion", server_random + client_random, key_block_len)

# Step 3: Extract keys
offset = 0
client_mac_key = key_block[offset:offset+20]; offset += 20
server_mac_key = key_block[offset:offset+20]; offset += 20
client_write_key = key_block[offset:offset+16]; offset += 16
server_write_key = key_block[offset:offset+16]; offset += 16
client_iv = key_block[offset:offset+16]; offset += 16
server_iv = key_block[offset:offset+16]; offset += 16

# 결과 출력
print("client_write_MAC_key:", client_mac_key.hex())
print("client_write_key:", client_write_key.hex())
print("client_IV:", client_iv.hex())
print("server_write_MAC_key:", server_mac_key.hex())
print("server_write_key:", server_write_key.hex())
print("server_IV:", server_iv.hex())
