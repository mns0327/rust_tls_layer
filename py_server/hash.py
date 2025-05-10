import hashlib
import hmac

print(hmac.new(b'1234567890', b'1234567890', hashlib.sha256).digest().hex())

# hmac_sha256_raw.py

import struct

# SHA256 constants
K = [
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
]

def rightrotate(x, n):
    return (x >> n) | (x << (32 - n)) & 0xffffffff

def sha256(msg: bytes) -> bytes:
    print("msg")
    print(msg)
    h = [
        0x6a09e667, 0xbb67ae85,
        0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19
    ]

    ml = len(msg) * 8
    msg += b'\x80'
    while (len(msg) * 8) % 512 != 448:
        msg += b'\x00'
    msg += struct.pack('>Q', ml)

    for i in range(0, len(msg), 64):
        w = list(struct.unpack('>16L', msg[i:i + 64])) + [0] * 48
        print(w)
        for j in range(16, 64):
            s0 = rightrotate(w[j-15], 7) ^ rightrotate(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = rightrotate(w[j-2], 17) ^ rightrotate(w[j-2], 19) ^ (w[j-2] >> 10)
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xffffffff
            print(f"w[{j}]: {w[j]}")

        a, b, c, d, e, f, g, h0 = h
        for j in range(64):
            S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h0 + S1 + ch + K[j] + w[j]) & 0xffffffff
            S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff

            h0 = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        h = [(x + y) & 0xffffffff for x, y in zip(h, [a, b, c, d, e, f, g, h0])]

    return b''.join(struct.pack('>I', x) for x in h)

def hmac_sha256(key: bytes, message: bytes) -> str:
    block_size = 64
    if len(key) > block_size:
        key = sha256(key)
    print(key.hex())
    key = key.ljust(block_size, b'\x00')
    print(key.hex())
    o_key_pad = bytes([b ^ 0x5c for b in key])
    i_key_pad = bytes([b ^ 0x36 for b in key])
    return sha256(o_key_pad + sha256(i_key_pad + message)).hex()

# ✅ 결과
print(hmac_sha256(b'a', b'b'))