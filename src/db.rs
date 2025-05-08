use std::fmt;

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

struct TLS {
    version: u16,
    handshake: TlsHandshakeProtocol,
}

struct TlsHandshakeProtocol {
    version: u16,
    random: [u8; 32],
    session_id: [u8; 32],
    cipher_suites: Vec<CipherSuite>,
    compression_methods: [u8; 1],
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
