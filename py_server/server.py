from tlslite.api import *
import socket

# from tlslite.keyexchange import RSAKeyExchange
# from tlslite.handshakesettings import HandshakeSettings
# from tlslite.tlsconnection import TLSConnection

# original_calc_master_secret = TLSConnection._calcMasterSecret

# def debug_calc_master_secret(self, preMasterSecret, clientRandom, serverRandom):
#     print("🔍 PreMasterSecret:", preMasterSecret.hex())
#     masterSecret = original_calc_master_secret(self, preMasterSecret, clientRandom, serverRandom)
#     print("🔑 MasterSecret (early):", masterSecret.hex())
#     return masterSecret

# TLSConnection._calcMasterSecret = debug_calc_master_secret

with open("cert.pem", "rb") as f:
    cert_chain = X509CertChain([X509().parse(f.read().decode())])
with open("key.pem", "rb") as f:
    private_key = parsePEMKey(f.read().decode(), private=True)

sock = socket.socket()
sock.bind(("", 4433))
sock.listen(10)
print("Waiting for connection...")

while True:
    try:
        conn, addr = sock.accept()
        print(f"Connection from {addr}")

        tls_conn = TLSConnection(conn)
        tls_conn.handshakeServer(certChain=cert_chain, privateKey=private_key)

        print(">>> MASTER SECRET:")
        print(tls_conn.session.masterSecret.hex())
    except Exception as e:
        print(f"Error: {e}")
        continue