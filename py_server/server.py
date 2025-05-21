import socket
import ssl
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

def generate_self_signed_cert(cert_file='server.crt', key_file='server.key'):
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"Already exists: {cert_file}, {key_file}")
        return
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"KR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Seoul"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Gangnam"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"Self-signed certificate and key generated: {cert_file}, {key_file}")

def create_tls_echo_server(host='0.0.0.0', port=8443):
    # 인증서와 키 생성
    generate_self_signed_cert()
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    
    print(f"TLS Echo Server start at {host}:{port}...")
    
    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"[*] Client connected: {addr}")
            
            ssl_client_socket = context.wrap_socket(client_socket, server_side=True)
            
            try:
                while True:
                    data = ssl_client_socket.recv(1024)
                    if not data:
                        break
                    print(f"[*] Received data: {data.decode()}")
                    ssl_client_socket.send(data)
            
            except ssl.SSLError as e:
                print(f"[*] SSL Error: {e}")
            except Exception as e:
                print(f"[*] Error: {e}")
            finally:
                ssl_client_socket.close()
                
    except KeyboardInterrupt:
        print("\n[*] Server is shutting down...")
    finally:
        server_socket.close()

if __name__ == '__main__':
    create_tls_echo_server()



# def rsa_encrypt_raw_pkcs1(message: bytes, e: int, n: int) -> bytes:
#     """Encrypt with raw RSA and manual PKCS#1 v1.5 padding."""
#     k = (n.bit_length() + 7) // 8
#     padded = pkcs1_v1_5_pad(message, k)
#     m_int = int.from_bytes(padded, byteorder='big')
#     c_int = pow(m_int, e, n)
#     return c_int.to_bytes(k, byteorder='big')