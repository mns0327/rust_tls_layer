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
print(master_secret.hex())