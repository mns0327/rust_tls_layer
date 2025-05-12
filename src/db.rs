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
                write!(f, "{}", name)
            }
        }
    };
}

pub struct TLS {
    version: u16,
    pub handshake: TlsHandshakeProtocol,
}

impl TLS {
    pub fn new() -> Self {
        Self {
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
}

impl fmt::Display for TLS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS Layer: 1.3\n- Content Type: Handshake(22)\n- Version: {}\n- Handshake Protocol: \n{}", self.version, self.handshake)
    }
}

pub struct TlsHandshakeProtocol {
    version: u16,
    pub random: [u8; 32],
    session_id: [u8; 32],
    cipher_suites: Vec<CipherSuite>,
}

impl fmt::Display for TlsHandshakeProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "  - Handshake type: ClientHello\n  - Version: {}\n  - Random: {}\n  - Session ID: {}\n  - Cipher Suites: {}", self.version, self.random.to_vec().hex_display(), self.session_id.to_vec().hex_display(), self.cipher_suites.iter().map(|s| s.to_string()).collect::<Vec<String>>().join(", "))
    }
}

impl TlsHandshakeProtocol {
    pub fn new() -> Self {
        Self {
            version: 0x0303,    // TLS 1.2
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
            ]
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.push(1);                    // Handshake Type: Client Hello (1) 1 bytes
        vec.extend([0, 0, 0]);       // Length 3 bytes
        vec.extend([3, 3]);         // Version TLS 1.2 (0x0303) 2 bytes
        vec.extend(self.random);    // Random   32 bytes
        vec.extend([self.session_id.len() as u8]);    // Session ID Length 1 bytes
        vec.extend(self.session_id);  // Session ID 32 bytes
        let cipher_suites_bytes = self.cipher_suites.iter()
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
