from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import binascii

# 개인키 로드
with open("key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# ClientKeyExchange로부터 받은 암호문 (예: 256바이트 RSA 암호문)
encrypted_pms_hex = "7d7c663ca7c405e580bd7d06aadb2075f8cd4982af00fd89aea2348488d01a3cb438e15985a71eb7d4d9dbb49d01f4364b05e0d80b5ba12799f6e94c76aee4d1940ab146336b812de857bad76fc8aefedf73beb3675d13b243b177e60c2f8629182b8421b89b68b9f8670a8532f20e2960b39d2a61eac05a1d017adce2408c5cda848864e44b401ed34bee74a98409b1eef0087d133382acd42ba54a60b26ddc3a6d0cd02877311781fd83c0d18c33a97e41ee61d7bfd78542405092020436ee4000aa93c83904b10d9a27362264da20fbaa637d9d964aa1bf059c8943ba3203ded6aa0a2a0e1181c55e20d347578dc42fab9262de8059ad2724238f36bee702"  # 실제 값으로 교체
encrypted_pms = binascii.unhexlify(encrypted_pms_hex)

# 복호화 (PMS 획득)
pms = private_key.decrypt(
    encrypted_pms,
    padding.PKCS1v15()
)

print(f"[+] PMS: {pms.hex()}")