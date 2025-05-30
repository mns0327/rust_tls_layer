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
        finished = 20,
        unknown = 255
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeFragment {
    // HelloRequest(HelloRequest),
    ClientHello(HandshakeClientHello),
    ServerHello(HandshakeServerHello),
    Certificate(HandshakeCertificate),
    // ServerKeyExchange(ServerKeyExchange),
    // CertificateRequest(CertificateRequest),
    ServerHelloDone(ServerHelloDone),
    // CertificateVerify(CertificateVerify),
    ClientKeyExchange(ClientKeyExchange),
    Finished(Finished),
    Unknown(Vec<u8>),
}

impl HandshakeFragment {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            HandshakeFragment::ClientHello(client_hello) => client_hello.to_vec(),
            HandshakeFragment::ServerHello(server_hello) => server_hello.to_vec(),
            HandshakeFragment::ClientKeyExchange(client_key_exchange) => client_key_exchange.to_vec(),
            HandshakeFragment::Certificate(certificate) => certificate.to_vec(),
            HandshakeFragment::ServerHelloDone(server_hello_done) => server_hello_done.to_vec(),
            HandshakeFragment::Finished(finished) => finished.to_vec(),
            HandshakeFragment::Unknown(unknown) => unknown.clone(),
            _ => panic!("Unsupported handshake fragment: {:?}", self)
        }
    }

    pub fn from_vec(vec: Vec<u8>, msg_type: HandshakeType) -> Self {
        let fragment = match msg_type {
            HandshakeType::client_hello => HandshakeFragment::ClientHello(HandshakeClientHello::from_vec(vec)),
            HandshakeType::server_hello => HandshakeFragment::ServerHello(HandshakeServerHello::from_vec(vec)),
            HandshakeType::certificate => HandshakeFragment::Certificate(HandshakeCertificate::from_vec(vec)),
            HandshakeType::server_hello_done => HandshakeFragment::ServerHelloDone(ServerHelloDone::new()),
            
            _ => panic!("Unsupported handshake fragment: {:?}", msg_type)
        };
        fragment
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn new(verify_data: Vec<u8>) -> Self {
        Self { verify_data }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend(self.verify_data.clone());
        vec
    }

}

#[derive(Debug, PartialEq, Eq)]
pub struct HandshakeClientHello {
    version: ProtocolVersion,
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub cipher_suites: Vec<CipherSuite>,
    pub compression_methods: Vec<CompressionMethod>,
}

impl HandshakeClientHello {
    pub fn new() -> Self {
        Self {
            version: ProtocolVersion::new(3, 3),
            random: rand(),
            session_id: rand(),
            cipher_suites: vec![
                // CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                // CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                // CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                // CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                // CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                // CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
                // CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,
                // CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                // CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                // CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                // CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                // CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
                // CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256
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
        vec.extend([0, 0x8]); // Extensions Length 2 bytes
        vec.extend([0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x01]);   // TODO: hardcode
        
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

#[derive(Debug, PartialEq, Eq)]
pub struct HandshakeServerHello {
    version: ProtocolVersion,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub chosen_cipher: CipherSuite,
    pub compression_method: CompressionMethod,
}

impl HandshakeServerHello {
    pub fn new() -> Self {
        Self {
            version: ProtocolVersion::new(3, 3),
            random: rand(),
            session_id: rand().to_vec(),
            chosen_cipher: CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            compression_method: CompressionMethod::null,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend(self.version.to_vec());
        vec.extend(self.random);
        vec.extend([self.session_id.len() as u8]);
        vec.extend(self.session_id.clone());
        vec.extend(self.chosen_cipher.to_vec());
        vec.extend([self.compression_method.to_vec()[1]]);
        vec
    }

    fn from_vec(vec: Vec<u8>) -> Self {
        let version = ProtocolVersion::new(vec[0], vec[1]);
        let random = vec[2..34].try_into().unwrap();
        let session_id_len = vec[34];
        let session_id: Vec<u8> = if session_id_len == 0 {
            vec![]
        } else {
            vec[35..35 + session_id_len as usize].to_vec()
        };
        let cipher_start = 35 + session_id_len as usize;
        let chosen_cipher = CipherSuite::from_u16(u16::from_be_bytes([vec[cipher_start], vec[cipher_start + 1]])).unwrap();
        let compression_method = CompressionMethod::from_u16(u16::from_be_bytes([0, vec[cipher_start + 2]])).unwrap();
        Self { version: version, random, session_id, chosen_cipher, compression_method }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServerHelloDone {
    msg_type: HandshakeType,
    length: u32,
    fragment: Vec<u8>,
}

impl ServerHelloDone {
    pub fn new() -> Self {
        Self { msg_type: HandshakeType::server_hello_done, length: 0, fragment: vec![] }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        // vec.extend([self.msg_type.to_vec()[1]]);
        // let length_vec = u32::to_be_bytes(self.length);
        // vec.extend([length_vec[1], length_vec[2], length_vec[3]]);
        // vec.extend(self.fragment.clone());
        vec
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Handshake {
    pub msg_type: HandshakeType,
    length: u32,    // u24
    pub fragment: HandshakeFragment,
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
            HandshakeType::client_key_exchange => {
                HandshakeFragment::ClientKeyExchange(ClientKeyExchange::new())
            }
            HandshakeType::finished => {
                HandshakeFragment::Finished(Finished::new(vec![]))
            }
            HandshakeType::unknown => {
                HandshakeFragment::Unknown(vec![])
            }
            _ => {
                panic!("Unsupported handshake type: {:?}", msg_type);
            }
        };
        Self { msg_type, length: 0, fragment: fragment }
    }

    pub fn to_vec(&mut self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();

        if self.msg_type == HandshakeType::unknown {
            vec.extend(self.fragment.to_vec());
        } else {
            vec.extend([self.msg_type.to_vec()[1]]);
            self.length = self.fragment.to_vec().len() as u32;
            let length_vec = u32::to_be_bytes(self.length);
            vec.extend([length_vec[1], length_vec[2], length_vec[3]]);
            vec.extend(self.fragment.to_vec());
        }

        vec
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        let msg_type = HandshakeType::from_u16(u16::from_be_bytes([0, vec[0]])).unwrap();
        let length = u32::from_be_bytes([0, vec[1], vec[2], vec[3]]);
        let fragment = HandshakeFragment::from_vec(vec[4..].to_vec(), msg_type);
        Self { msg_type, length, fragment }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct HandshakeCertificate {
    length: u32,
    pub tbsCertificate: Vec<Certificate>,
}

impl HandshakeCertificate {
    pub fn new() -> Self {
        Self { length: 0, tbsCertificate: vec![] }
    }

    pub fn to_vec(&self) -> Vec<u8> {   // TODO: 
        let mut vec: Vec<u8> = Vec::new();
        let length_vec = u32::to_be_bytes(self.length);
        vec.extend([length_vec[1], length_vec[2], length_vec[3]]);
        let cert_bytes: Vec<Vec<u8>> = self.tbsCertificate.iter().map(|tbs| tbs.to_vec()).collect();
        for cert_byte in cert_bytes {
            let length_vec = u32::to_be_bytes(cert_byte.len() as u32);
            vec.extend([length_vec[1], length_vec[2], length_vec[3]]);
            vec.extend(cert_byte);
        }
        vec
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        let certificate_length: u32 = u32::from_be_bytes([0, vec[0], vec[1], vec[2]]);
        let mut tbs_certificates: Vec<Certificate> = vec![];

        let mut offset: usize = 3;
        while offset < certificate_length as usize + 3 {
            let length = u32::from_be_bytes([0, vec[offset], vec[offset + 1], vec[offset + 2]]);
            offset += 3;
            let tbs_certificate = Certificate::from_vec(vec[offset..offset + length as usize].to_vec());
            println!("tbs_certificate: {:?}", vec[offset..offset + length as usize].to_vec().hex_display());
            tbs_certificates.push(tbs_certificate);
            offset += length as usize;
        }

        Self { length: certificate_length, tbsCertificate: tbs_certificates }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ClientKeyExchange {
    pub length: u32,
    pub fragment: Vec<u8>,
}

impl ClientKeyExchange {
    pub fn new() -> Self {
        Self { length: 0, fragment: vec![] }
    }

    pub fn from_key(key: Vec<u8>) -> Self {
        let length = key.len() as u32;
        let fragment = key;
        Self { length, fragment }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend(u16::to_be_bytes(self.fragment.len() as u16));
        vec.extend(self.fragment.clone());
        vec
    }
}