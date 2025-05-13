use std::fmt::{self, write};
use crate::rand::rand;
use crate::hash::{VecStructU8, hmac_sha256};

macro_rules! define_cipher_suite {
    ($($variant:ident = $value:expr),*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum CipherSuite {
            $($variant = $value),*
        }

        impl CipherSuite {
            pub fn from_u16(value: u16) -> Option<Self> {
                match value {
                    $($value => Some(Self::$variant),)*
                    _ => None
                }
            }

            pub fn to_u16(self) -> u16 {
                match self {
                    $(Self::$variant => $value,)*
                }
            }

            pub fn to_vec(self) -> Vec<u8> {
                let mut vec: Vec<u8> = Vec::new();
                vec.extend(self.to_u16().to_be_bytes());
                vec
            }
        }

        impl fmt::Display for CipherSuite {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let name = match self {
                    $(Self::$variant => stringify!($variant),)*
                };
                write!(f, "0x{:04x}({})", self.to_u16(), name)
            }
        }
    };
}

pub struct TLS {
    content_type: u8,
    version: u16,
    pub handshake: TlsHandshakeProtocol,
}

impl TLS {
    pub fn new() -> Self {
        Self {
            content_type: 22,
            version: 0x0301,    // TLS 1.0
            handshake: TlsHandshakeProtocol::new(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend([22]);     // Content Type: HandShake (22) 1 bytes
        vec.extend([3, 1]);         // Version TLS 1.2 (0x0303) 2 bytes

        let handshake_vec = self.handshake.to_vec();
        vec.extend(handshake_vec.len().to_vec(2));  // 2바이트로 길이 표현
        vec.extend(handshake_vec);
        vec
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        let content_type = vec[0];
        let version = u16::from_be_bytes([vec[1], vec[2]]);
        let handshake_len = u16::from_be_bytes([vec[3], vec[4]]);
        let handshake_bytes = vec[5..(5 + handshake_len as usize)].to_vec();
        println!("handshake_bytes: {:?}", handshake_bytes.hex_display());

        Self {
            content_type: content_type,
            version: version,    // TLS 1.0
            handshake: TlsHandshakeProtocol::from_vec(handshake_bytes),
        }
    }
}

impl fmt::Display for TLS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS Layer: 1.3\n- Content Type: Handshake(22)\n- Version: {}\n- Handshake Protocol: \n{}", self.version, self.handshake)
    }
}

pub struct TlsHandshakeProtocol {
    handshake_type: Handshake_type,
    version: u16,
    pub random: Option<[u8; 32]>,
    session_id: Option<[u8; 32]>,
    cipher_suites: Option<Vec<CipherSuite>>,
    chosen_cipher: Option<CipherSuite>,
    certificate: Option<Vec<Vec<u8>>>,
}

impl fmt::Display for TlsHandshakeProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.handshake_type == Handshake_type::ClientHello {
            write!(f, "  - Handshake type: {}\n  - Version: {}\n  - Random: {}\n  - Session ID: {}\n  - Cipher Suites: {}", self.handshake_type.to_string(), self.version, self.random.as_ref().unwrap().to_vec().hex_display(), self.session_id.as_ref().unwrap().to_vec().hex_display(), self.cipher_suites.as_ref().unwrap().iter().map(|s| s.to_string()).collect::<Vec<String>>().join(", "))
        } else if self.handshake_type == Handshake_type::ServerHello {
            write!(f, "  - Handshake type: {}\n  - Version: {}\n  - Random: {}\n  - Session ID: {}\n  - Cipher Suites: {}", self.handshake_type.to_string(), self.version, self.random.as_ref().unwrap().to_vec().hex_display(), self.session_id.as_ref().unwrap().to_vec().hex_display(), self.chosen_cipher.as_ref().unwrap().to_string())
        } else if self.handshake_type == Handshake_type::Certificate {
            write!(f, "  - Handshake type: {}\n  - Version: {}\n", self.handshake_type.to_string(), self.version)
        } else {
            write!(f, "  - Handshake type: {}\n  - Version: {}\n", self.handshake_type.to_string(), self.version)
        }
    }
}

impl TlsHandshakeProtocol {
    pub fn new() -> Self {
        Self {
            handshake_type: Handshake_type::ClientHello,
            version: 0x0303,    // TLS 1.2
            random: Some(rand()),
            session_id: Some(rand()),
            cipher_suites: Some(vec![
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
            ]),
            chosen_cipher: None,
            certificate: None,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend([self.handshake_type.to_u8()]);      // Handshake Type: Client Hello (1) 1 bytes
        vec.extend([0, 0, 0]);       // Length 3 bytes
        vec.extend([3, 3]);         // Version TLS 1.2 (0x0303) 2 bytes
        vec.extend(self.random.as_ref().unwrap());    // Random   32 bytes
        vec.extend([self.session_id.as_ref().unwrap().len() as u8]);    // Session ID Length 1 bytes
        vec.extend(self.session_id.as_ref().unwrap());  // Session ID 32 bytes
        let cipher_suites_bytes = self.cipher_suites.as_ref().unwrap().iter()
            .flat_map(|s| s.to_vec())
            .collect::<Vec<u8>>();
        vec.extend((cipher_suites_bytes.len() as u16).to_be_bytes());   // Cipher Suite Length 2 bytes
        vec.extend(cipher_suites_bytes);        // cipher suites
        vec.extend([1]);    // Compression Methods Length 1 bytes
        vec.extend([0]);    // Compression Methods null 1 bytes
        vec.extend([0, 0]); // Extensions Length 2 bytes
        
        let length_vec = (vec.len() - 4).to_vec(3);
        vec[1..4].copy_from_slice(&length_vec);
        // ... Extensions 
        vec
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        let handshake_type = vec[0];
        match handshake_type {
            2 => {
                let content_len = u32::from_be_bytes([0, vec[1], vec[2], vec[3]]);
                let version = u16::from_be_bytes([vec[4], vec[5]]);
                let random: [u8; 32] = vec[6..38].try_into().unwrap();
                let session_id_len = vec[38];
                let session_id: [u8; 32] = vec[39..(39 + session_id_len as usize)].try_into().unwrap();
                let cipher_suite = CipherSuite::from_u16(u16::from_be_bytes([vec[(39 + session_id_len) as usize], vec[(39 + session_id_len + 1) as usize]])).unwrap();
                Self {
                    handshake_type: Handshake_type::from_u8(handshake_type).unwrap(),
                    version: version,
                    random: Some(random),
                    session_id: Some(session_id),
                    cipher_suites: None,
                    chosen_cipher: Some(cipher_suite),
                    certificate: None,
                }
            }
            0x0b => {
                let content_len = u32::from_be_bytes([0, vec[1], vec[2], vec[3]]);
                let certificate_list_len = u32::from_be_bytes([0, vec[4], vec[5], vec[6]]) as usize;
                println!("certificate_list_len: {}", certificate_list_len);
                let mut offset: usize = 7;
                let mut certificate_list: Vec<Vec<u8>> = Vec::new();
                while offset < certificate_list_len + 7 {
                    let certificate_len = u32::from_be_bytes([0, vec[offset], vec[offset + 1], vec[offset + 2]]) as usize;
                    offset += 3;
                    let certificate = vec[offset..offset+certificate_len].to_vec();
                    offset += certificate_len;
                    certificate_list.push(certificate);
                }
                Self {
                    handshake_type: Handshake_type::from_u8(handshake_type).unwrap(),
                    version: 0x0303,
                    random: None,
                    session_id: None,
                    cipher_suites: None,
                    chosen_cipher: None,
                    certificate: Some(certificate_list),
                }
            }
            _ => panic!("Unsupported handshake type: {}", handshake_type)
        }
    }
}

trait usizeToVec {
    fn to_vec(&self, padding: usize) -> Vec<u8>; 
}

impl usizeToVec for usize {
    fn to_vec(&self, padding: usize) -> Vec<u8> {
        let mut vec = Vec::<u8>::with_capacity(padding);
        vec.resize(padding, 0);
        for i in 0..padding {
            vec[padding - i - 1] = ((self >> (i * 8)) & 0xFF) as u8;
        }
        vec
    }
}

define_cipher_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027,
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x9c,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x3c,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028,
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x9d,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x3d
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handshake_type {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 0x0b,
}

impl Handshake_type {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ClientHello),
            2 => Some(Self::ServerHello),
            0x0b => Some(Self::Certificate),
            _ => None
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::ClientHello => 1,
            Self::ServerHello => 2,
            Self::Certificate => 0x0b,
        }
    }

    pub fn to_string(self) -> String {
        match self {
            Self::ClientHello => "ClientHello".to_string(),
            Self::ServerHello => "ServerHello".to_string(),
            Self::Certificate => "Certificate".to_string(),
        }
    }
}