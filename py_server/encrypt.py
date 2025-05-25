from cryptography.hazmat.primitives.ciphers.aead import AESGCM

client_write_key = b'\x00' * 16
nonce = b'\x00' * 12
finished_plaintext = b'\x00' * 12

aesgcm = AESGCM(client_write_key)
aad = b'\x16\x03\x03'

ciphertext = aesgcm.encrypt(nonce, finished_plaintext, aad)
print(ciphertext)

from Crypto.Cipher import AES
import struct

# Galois field multiplication in GF(2^128)
def gf_mul(x: int, y: int) -> int:
    R = 0xe1000000000000000000000000000000
    z = 0
    for i in range(128):
        if y & (1 << (127 - i)):
            z ^= x
        if x & 1:
            x = (x >> 1) ^ R
        else:
            x >>= 1
    return z

# Pad a byte string to 16-byte blocks
def pad16(data: bytes) -> bytes:
    if len(data) % 16 == 0:
        return data
    return data + b'\x00' * (16 - len(data) % 16)

# GHASH function: GHASH(H, A, C)
def ghash(H: bytes, A: bytes, C: bytes) -> bytes:
    H_int = int.from_bytes(H, 'big')
    Y = 0

    def process_blocks(data):
        nonlocal Y
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            X = int.from_bytes(block, 'big')
            Y = gf_mul(Y ^ X, H_int)

    process_blocks(pad16(A))
    process_blocks(pad16(C))
    print("A", pad16(A).hex())
    print("C", pad16(C).hex())
    print("Y", Y.to_bytes(16, 'big').hex())

    a_len = (len(A) * 8).to_bytes(8, 'big')
    c_len = (len(C) * 8).to_bytes(8, 'big')
    length_block = a_len + c_len
    Y = gf_mul(Y ^ int.from_bytes(length_block, 'big'), H_int)

    return Y.to_bytes(16, 'big')

# AES-GCM encryption (low-level, simplified)
def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes):
    aes = AES.new(key, AES.MODE_ECB)
    H = aes.encrypt(b'\x00' * 16)
    print(len(H))
    J0 = iv + b'\x00\x00\x00\x01'

    def inc32(counter):
        value = struct.unpack('>I', counter[-4:])[0]
        value = (value + 1) & 0xffffffff
        return counter[:-4] + struct.pack('>I', value)

    ctr = inc32(J0)
    ciphertext = b''
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        print(block.hex())
        keystream = aes.encrypt(ctr)
        ctr = inc32(ctr)
        ciphertext_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
        ciphertext += ciphertext_block

    S = ghash(H, aad, ciphertext)
    tag = bytes(a ^ b for a, b in zip(aes.encrypt(J0), S))

    return ciphertext, tag

# AES-GCM decryption (low-level)
def aes_gcm_decrypt_tag(key: bytes, iv: bytes, ciphertext_and_tag: bytes, aad: bytes):
    aes = AES.new(key, AES.MODE_ECB)
    H = aes.encrypt(b'\x00' * 16)
    print(H.hex())
    J0 = iv + b'\x00\x00\x00\x01'

    tag = ciphertext_and_tag[-16:]
    ciphertext = ciphertext_and_tag[:-16]

    def inc32(counter):
        value = struct.unpack('>I', counter[-4:])[0]
        value = (value + 1) & 0xffffffff
        return counter[:-4] + struct.pack('>I', value)

    ctr = inc32(J0)
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        keystream = aes.encrypt(ctr)
        ctr = inc32(ctr)
        plaintext_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
        plaintext += plaintext_block
    S = ghash(H, aad, ciphertext)
    computed_tag = bytes(a ^ b for a, b in zip(aes.encrypt(J0), S))

    if computed_tag != tag:
        raise ValueError("Authentication failed: GCM tag mismatch")

    return plaintext

# Demo values
key = b'\x00' * 16
iv = b'\x00' * 12

ciphertext, tag = aes_gcm_encrypt(key, iv, finished_plaintext, aad)
decrypted = aes_gcm_decrypt_tag(key, iv, ciphertext + tag, aad)

print((ciphertext + tag).hex())
print(decrypted.hex())

# def aes_encrypt_block(plaintext_block: bytes, key: bytes) -> bytes:
#     def sub_bytes(state):
#         return [s_box[b] for b in state]

#     def shift_rows(state):
#         return [
#             state[0], state[5], state[10], state[15],
#             state[4], state[9], state[14], state[3],
#             state[8], state[13], state[2], state[7],
#             state[12], state[1], state[6], state[11]
#         ]

#     def xtime(a):
#         return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)

#     def mix_columns(state):
#         res = []
#         for i in range(4):
#             col = state[i*4:(i+1)*4]
#             res += [
#                 xtime(col[0]) ^ xtime(col[1]) ^ col[1] ^ col[2] ^ col[3],
#                 col[0] ^ xtime(col[1]) ^ xtime(col[2]) ^ col[2] ^ col[3],
#                 col[0] ^ col[1] ^ xtime(col[2]) ^ xtime(col[3]) ^ col[3],
#                 xtime(col[0]) ^ col[0] ^ col[1] ^ col[2] ^ xtime(col[3])
#             ]
#         return res

#     def add_round_key(state, key):
#         return [s ^ k for s, k in zip(state, key)]

#     def key_expansion(key):
#         key_columns = [key[i:i+4] for i in range(0, 16, 4)]
#         i = 0
#         while len(key_columns) < 44:
#             word = list(key_columns[-1])
#             if len(key_columns) % 4 == 0:
#                 word = [s_box[word[(j+1)%4]] for j in range(4)]
#                 word[0] ^= Rcon[i]
#                 i += 1
#             word = [a ^ b for a, b in zip(word, key_columns[-4])]
#             key_columns.append(word)
#         return [b for word in key_columns for b in word]

#     state = list(plaintext_block)
#     expanded_key = key_expansion(key)
#     state = add_round_key(state, expanded_key[:16])
#     for round in range(1, 10):
#         state = sub_bytes(state)
#         state = shift_rows(state)
#         state = mix_columns(state)
#         state = add_round_key(state, expanded_key[round*16:(round+1)*16])
#     state = sub_bytes(state)
#     state = shift_rows(state)
#     state = add_round_key(state, expanded_key[160:])
#     return bytes(state)

# ------------------------------------------------------------

# s_box = [
#     # 0     1      2     3     4     5     6     7     8     9     A     B     C     D     E     F
#     0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,  # 0
#     0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,  # 1
#     0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,  # 2
#     0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,  # 3
#     0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,  # 4
#     0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,  # 5
#     0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,  # 6
#     0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,  # 7
#     0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,  # 8
#     0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,  # 9
#     0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,  # A
#     0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,  # B
#     0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,  # C
#     0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,  # D
#     0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,  # E
#     0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16   # F
# ]

# # Round constant
# Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]



# # AES mode switchable encryption: ECB, CBC, CTR
# def xor_bytes(a: bytes, b: bytes) -> bytes:
#     return bytes(x ^ y for x, y in zip(a, b))

# def split_blocks(data: bytes, block_size: int = 16) -> list:
#     return [data[i:i+block_size] for i in range(0, len(data), block_size)]

# def pad(data: bytes, block_size: int = 16) -> bytes:
#     pad_len = block_size - len(data) % block_size
#     return data + bytes([pad_len] * pad_len)

# def unpad(data: bytes) -> bytes:
#     pad_len = data[-1]
#     if not 0 < pad_len <= 16:
#         raise ValueError("Invalid padding")
#     return data[:-pad_len]

# def aes_encrypt_block(plaintext, key):  # From previous implementation
#     def sub_bytes(state):
#         return [s_box[b] for b in state]

#     def shift_rows(state):
#         return [
#             state[0], state[5], state[10], state[15],
#             state[4], state[9], state[14], state[3],
#             state[8], state[13], state[2], state[7],
#             state[12], state[1], state[6], state[11]
#         ]

#     def xtime(a):
#         return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)

#     def mix_columns(state):
#         res = []
#         for i in range(4):
#             col = state[i*4:(i+1)*4]
#             res += [
#                 xtime(col[0]) ^ xtime(col[1]) ^ col[1] ^ col[2] ^ col[3],
#                 col[0] ^ xtime(col[1]) ^ xtime(col[2]) ^ col[2] ^ col[3],
#                 col[0] ^ col[1] ^ xtime(col[2]) ^ xtime(col[3]) ^ col[3],
#                 xtime(col[0]) ^ col[0] ^ col[1] ^ col[2] ^ xtime(col[3])
#             ]
#         return res

#     def add_round_key(state, key):
#         return [s ^ k for s, k in zip(state, key)]

#     def key_expansion(key):
#         key_columns = [key[i:i+4] for i in range(0, 16, 4)]
#         i = 0
#         while len(key_columns) < 44:
#             word = list(key_columns[-1])
#             if len(key_columns) % 4 == 0:
#                 word = [s_box[word[(j+1)%4]] for j in range(4)]
#                 word[0] ^= Rcon[i]
#                 i += 1
#             word = [a ^ b for a, b in zip(word, key_columns[-4])]
#             key_columns.append(word)
#         return [b for word in key_columns for b in word]

#     state = list(plaintext)
#     expanded_key = key_expansion(key)
#     print(expanded_key)
#     state = add_round_key(state, expanded_key[:16])
#     for round in range(1, 10):
#         state = sub_bytes(state)
#         state = shift_rows(state)
#         state = mix_columns(state)
#         state = add_round_key(state, expanded_key[round*16:(round+1)*16])
#     state = sub_bytes(state)
#     state = shift_rows(state)
#     state = add_round_key(state, expanded_key[160:])
#     return bytes(state)

# def aes_encrypt(data: bytes, key: bytes, mode: str = 'ECB', iv: bytes = None) -> bytes:
#     data = pad(data)
#     blocks = split_blocks(data)
#     result = []
#     if mode == 'ECB':
#         for block in blocks:
#             result.append(aes_encrypt_block(block, key))
#     elif mode == 'CBC':
#         if iv is None:
#             raise ValueError("CBC mode requires IV")
#         prev = iv
#         for block in blocks:
#             xor_block = xor_bytes(block, prev)
#             enc_block = aes_encrypt_block(xor_block, key)
#             result.append(enc_block)
#             prev = enc_block
#     elif mode == 'CTR':
#         if iv is None:
#             raise ValueError("CTR mode requires IV (as nonce)")
#         counter = int.from_bytes(iv, 'big')
#         for i, block in enumerate(blocks):
#             counter_block = (counter + i).to_bytes(16, 'big')
#             keystream = aes_encrypt_block(counter_block, key)
#             result.append(xor_bytes(block, keystream[:len(block)]))
#     else:
#         raise ValueError("Unsupported mode")
#     return b''.join(result)

# # Test ECB, CBC, CTR with same key
# key = bytes([0x00] * 16)
# iv = bytes([0x00] * 16)
# plaintext = b"Hello AES Mode World!"  # 20 bytes

# ecb = aes_encrypt(plaintext, key, mode='ECB')
# cbc = aes_encrypt(plaintext, key, mode='CBC', iv=iv)
# ctr = aes_encrypt(plaintext, key, mode='CTR', iv=iv)

# ecb.hex(), cbc.hex(), ctr.hex()



# def aes_mode_encrypt(data: bytes, key: bytes, mode: str = 'ECB', iv: bytes = None) -> bytes:
#     data = pad(data)
#     blocks = split_blocks(data)
#     result = []

#     if mode == 'ECB':
#         for block in blocks:
#             result.append(aes_encrypt_block(block, key))
#     elif mode == 'CBC':
#         if iv is None:
#             raise ValueError("CBC mode requires IV")
#         prev = iv
#         for block in blocks:
#             xor_block = xor_bytes(block, prev)
#             enc_block = aes_encrypt_block(xor_block, key)
#             result.append(enc_block)
#             prev = enc_block
#     elif mode == 'CTR':
#         if iv is None:
#             raise ValueError("CTR mode requires IV (nonce)")
#         counter = int.from_bytes(iv, 'big')
#         for i, block in enumerate(blocks):
#             counter_block = (counter + i).to_bytes(16, 'big')
#             keystream = aes_encrypt_block(counter_block, key)
#             result.append(xor_bytes(block, keystream[:len(block)]))
#     else:
#         raise ValueError("Unsupported mode")

#     return b''.join(result)

# # Run test again with modular block function
# ecb = aes_mode_encrypt(plaintext, key, mode='ECB')
# cbc = aes_mode_encrypt(plaintext, key, mode='CBC', iv=iv)
# ctr = aes_mode_encrypt(plaintext, key, mode='CTR', iv=iv)

# ecb.hex(), cbc.hex(), ctr.hex()

# inv_s_box = [s_box.index(x) for x in range(256)]

# def aes_decrypt_block(ciphertext_block: bytes, key: bytes) -> bytes:
#     inv_s_box = [s_box.index(x) for x in range(256)]

#     def inv_shift_rows(state):
#         return [
#             state[0], state[13], state[10], state[7],
#             state[4], state[1], state[14], state[11],
#             state[8], state[5], state[2], state[15],
#             state[12], state[9], state[6], state[3]
#         ]

#     def xtime(a):
#         return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)

#     def mult(a, b):
#         result = 0
#         for i in range(8):
#             if b & 1:
#                 result ^= a
#             high_bit = a & 0x80
#             a = (a << 1) & 0xFF
#             if high_bit:
#                 a ^= 0x1B
#             b >>= 1
#         return result

#     def inv_mix_columns(state):
#         res = []
#         for i in range(4):
#             col = state[i*4:(i+1)*4]
#             res += [
#                 mult(col[0], 0x0e) ^ mult(col[1], 0x0b) ^ mult(col[2], 0x0d) ^ mult(col[3], 0x09),
#                 mult(col[0], 0x09) ^ mult(col[1], 0x0e) ^ mult(col[2], 0x0b) ^ mult(col[3], 0x0d),
#                 mult(col[0], 0x0d) ^ mult(col[1], 0x09) ^ mult(col[2], 0x0e) ^ mult(col[3], 0x0b),
#                 mult(col[0], 0x0b) ^ mult(col[1], 0x0d) ^ mult(col[2], 0x09) ^ mult(col[3], 0x0e),
#             ]
#         return res

#     def add_round_key(state, key):
#         return [s ^ k for s, k in zip(state, key)]

#     def key_expansion(key):
#         key_columns = [key[i:i+4] for i in range(0, 16, 4)]
#         i = 0
#         while len(key_columns) < 44:
#             word = list(key_columns[-1])
#             if len(key_columns) % 4 == 0:
#                 word = [s_box[word[(j+1)%4]] for j in range(4)]
#                 word[0] ^= Rcon[i]
#                 i += 1
#             word = [a ^ b for a, b in zip(word, key_columns[-4])]
#             key_columns.append(word)
#         return [b for word in key_columns for b in word]

#     state = list(ciphertext_block)
#     expanded_key = key_expansion(key)
#     state = add_round_key(state, expanded_key[160:])
#     for round in range(9, 0, -1):
#         state = inv_shift_rows(state)
#         state = [inv_s_box[b] for b in state]
#         state = add_round_key(state, expanded_key[round*16:(round+1)*16])
#         state = inv_mix_columns(state)
#     state = inv_shift_rows(state)
#     state = [inv_s_box[b] for b in state]
#     state = add_round_key(state, expanded_key[:16])
#     return bytes(state)

# def aes_mode_decrypt(ciphertext: bytes, key: bytes, mode: str = 'ECB', iv: bytes = None) -> bytes:
#     blocks = split_blocks(ciphertext)
#     result = []

#     if mode == 'ECB':
#         for block in blocks:
#             result.append(aes_decrypt_block(block, key))
#     elif mode == 'CBC':
#         if iv is None:
#             raise ValueError("CBC mode requires IV")
#         prev = iv
#         for block in blocks:
#             plain_block = aes_decrypt_block(block, key)
#             result.append(xor_bytes(plain_block, prev))
#             prev = block
#     elif mode == 'CTR':
#         if iv is None:
#             raise ValueError("CTR mode requires IV")
#         counter = int.from_bytes(iv, 'big')
#         for i, block in enumerate(blocks):
#             counter_block = (counter + i).to_bytes(16, 'big')
#             keystream = aes_encrypt_block(counter_block, key)
#             result.append(xor_bytes(block, keystream[:len(block)]))
#     else:
#         raise ValueError("Unsupported mode")

#     return b''.join(result) if mode == 'CTR' else unpad(b''.join(result))

# # Test decryption against known ciphertexts
# dec_ecb = aes_mode_decrypt(ecb, key, mode='ECB')
# dec_cbc = aes_mode_decrypt(cbc, key, mode='CBC', iv=iv)
# dec_ctr = aes_mode_decrypt(ctr, key, mode='CTR', iv=iv)

# dec_ecb.decode(), dec_cbc.decode(), dec_ctr.decode()
# print("--------------------------------")
# print(dec_ecb.decode())