use crate::{define_enum_macro, TLSPlaintext, ProtocolVersion, CipherSuite, CompressionMethod, usizeToVec};
use crate::rand::rand;
use crate::hash::{VecStructU8, hmac_sha256};
use crate::x509::Certificate;

define_enum_macro! {
    #[derive(Debug)]
    pub enum HandshakeType {
        hello_request = 0,
        client_hello = 1,
        server_hello = 2,
        certificate = 11,
        server_key_exchange = 12,
        certificate_request = 13,
        server_hello_done = 14,
        certificate_verify = 15,
        client_key_exchange = 16,
        finished = 20
    }
}

#[derive(Debug)]
pub enum HandshakeFragment {
    // HelloRequest(HelloRequest),
    ClientHello(HandshakeClientHello),
    ServerHello(HandshakeServerHello),
    Certificate(HandshakeCertificate),
    // ServerKeyExchange(ServerKeyExchange),
    // CertificateRequest(CertificateRequest),
    // ServerHelloDone(ServerHelloDone),
    // CertificateVerify(CertificateVerify),
    // ClientKeyExchange(ClientKeyExchange),
    // Finished(Finished),
}

impl HandshakeFragment {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            HandshakeFragment::ClientHello(client_hello) => client_hello.to_vec(),
            // HandshakeFragment::ServerHello(server_hello) => server_hello.to_vec(),
            _ => panic!("Unsupported handshake fragment: {:?}", self)
        }
    }

    pub fn from_vec(vec: Vec<u8>, msg_type: HandshakeType) -> Self {
        let fragment = match msg_type {
            HandshakeType::client_hello => HandshakeFragment::ClientHello(HandshakeClientHello::from_vec(vec)),
            HandshakeType::server_hello => HandshakeFragment::ServerHello(HandshakeServerHello::from_vec(vec)),
            HandshakeType::certificate => HandshakeFragment::Certificate(HandshakeCertificate::from_vec(vec)),
            _ => panic!("Unsupported handshake fragment: {:?}", msg_type)
        };
        fragment
    }
}
#[derive(Debug)]
struct HandshakeClientHello {
    version: ProtocolVersion,
    random: [u8; 32],
    session_id: [u8; 32],
    cipher_suites: Vec<CipherSuite>,
    compression_methods: Vec<CompressionMethod>,
}

impl HandshakeClientHello {
    pub fn new() -> Self {
        Self {
            version: ProtocolVersion::new(3, 3),
            random: rand(),
            session_id: rand(),
            cipher_suites: vec![
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256
            ],
            compression_methods: vec![CompressionMethod::null],
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend(self.version.to_vec());
        vec.extend(self.random);    // Random   32 bytes
        vec.extend([self.session_id.len() as u8]);    // Session ID Length 1 bytes
        vec.extend(self.session_id);  // Session ID 32 bytes
        let cipher_suites_bytes = self.cipher_suites.iter()
            .flat_map(|s| s.to_vec())
            .collect::<Vec<u8>>();
        vec.extend((cipher_suites_bytes.len() as u16).to_be_bytes());   // Cipher Suite Length 2 bytes
        vec.extend(cipher_suites_bytes);        // cipher suites
        vec.extend([self.compression_methods.len() as u8]);    // Compression Methods Length 1 bytes
        vec.extend(self.compression_methods.iter().flat_map(|s| [s.to_vec()[1]]).collect::<Vec<u8>>());    // Compression Methods null 1 bytes
        vec.extend([0, 0]); // Extensions Length 2 bytes
        
        // ... Extensions 
        vec
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        let version = ProtocolVersion::new(vec[0], vec[1]);
        let random = vec[2..34].try_into().unwrap();
        let session_id = vec[34..66].try_into().unwrap();
        let cipher_suites = vec[66..].iter().map(|s| CipherSuite::from_u16(u16::from_be_bytes([0, *s])).unwrap()).collect();
        let compression_methods = vec[66..].iter().map(|s| CompressionMethod::from_u16(u16::from_be_bytes([0, *s])).unwrap()).collect();
        Self {
            version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
        }
    }
}

#[derive(Debug)]
struct HandshakeServerHello {
    version: ProtocolVersion,
    random: [u8; 32],
    session_id: [u8; 32],
    chosen_cipher: CipherSuite,
    compression_method: CompressionMethod,
}

impl HandshakeServerHello {
    pub fn new() -> Self {
        Self {
            version: ProtocolVersion::new(3, 3),
            random: rand(),
            session_id: rand(),
            chosen_cipher: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            compression_method: CompressionMethod::null,
        }
    }

    fn from_vec(vec: Vec<u8>) -> Self {
        let version = ProtocolVersion::new(vec[0], vec[1]);
        let random = vec[2..34].try_into().unwrap();
        let session_id_len = vec[34];
        let session_id = vec[35..35 + session_id_len as usize].try_into().unwrap();
        let cipher_start = 35 + session_id_len as usize;
        let chosen_cipher = CipherSuite::from_u16(u16::from_be_bytes([vec[cipher_start], vec[cipher_start + 1]])).unwrap();
        let compression_method = CompressionMethod::from_u16(u16::from_be_bytes([0, vec[cipher_start + 2]])).unwrap();
        Self { version: version, random, session_id, chosen_cipher, compression_method }
    }
}

#[derive(Debug)]
pub struct Handshake {
    msg_type: HandshakeType,
    length: u32,    // u24
    fragment: HandshakeFragment,
}

impl Handshake {
    pub fn new(handshakeType: u32) -> Self {
        let msg_type = HandshakeType::from_u32(handshakeType).unwrap();

        let fragment: HandshakeFragment = match msg_type {
            HandshakeType::client_hello => {
                HandshakeFragment::ClientHello(HandshakeClientHello::new())
            }
            HandshakeType::server_hello => {
                HandshakeFragment::ServerHello(HandshakeServerHello::new())
            }
            _ => {
                panic!("Unsupported handshake type: {:?}", msg_type);
            }
        };
        Self { msg_type, length: 0, fragment: fragment }
    }

    pub fn to_vec(&mut self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend([self.msg_type.to_vec()[1]]);

        self.length = self.fragment.to_vec().len() as u32;
        let length_vec = u32::to_be_bytes(self.length);
        vec.extend([length_vec[1], length_vec[2], length_vec[3]]);
        vec.extend(self.fragment.to_vec());
        vec
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        let msg_type = HandshakeType::from_u16(u16::from_be_bytes([0, vec[0]])).unwrap();
        let length = u32::from_be_bytes([0, vec[1], vec[2], vec[3]]);
        let fragment = HandshakeFragment::from_vec(vec[4..].to_vec(), msg_type);
        Self { msg_type, length, fragment }
    }
}

#[derive(Debug)]
struct HandshakeCertificate {
    length: u32,
    tbsCertificate: Vec<Certificate>,
}

impl HandshakeCertificate {
    pub fn new() -> Self {
        Self { length: 0, tbsCertificate: vec![] }
    }

    // pub fn to_vec(&self) -> Vec<u8> {
    //     let mut vec: Vec<u8> = Vec::new();
    //     let length_vec = u32::to_be_bytes(self.length);
    //     vec.extend([length_vec[1], length_vec[2], length_vec[3]]);
    //     // vec.extend(self.tbsCertificate.iter().flat_map(|tbs| tbs.to_vec()).collect::<Vec<u8>>());
    //     vec
    // }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        let certificate_length: u32 = u32::from_be_bytes([0, vec[0], vec[1], vec[2]]);
        let mut tbs_certificates: Vec<Certificate> = vec![];

        let mut offset: usize = 3;
        while offset < certificate_length as usize + 3 {
            let length = u32::from_be_bytes([0, vec[offset], vec[offset + 1], vec[offset + 2]]);
            offset += 3;
            let tbs_certificate = Certificate::from_vec(vec[offset..offset + length as usize].to_vec());
            tbs_certificates.push(tbs_certificate);
            offset += length as usize;
        }

        Self { length: certificate_length, tbsCertificate: tbs_certificates }
    }
}