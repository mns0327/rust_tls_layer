use std::fmt::{self, write};
use crate::rand::rand;
use crate::hash::{VecStructU8, hmac_sha256};
use crate::handshake::{HandshakeType, Handshake, ClientKeyExchange, HandshakeFragment, Finished};

#[derive(Debug, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl ProtocolVersion {
    pub fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        vec![self.major, self.minor]
    }
}

#[macro_export]
macro_rules! define_enum_macro {
    (
        #[$outer:meta]
        $vis:vis enum $name:ident {
            $($variant:ident = $value:expr),* $(,)?
        }
    ) => {
        #[$outer]
        #[derive(Clone, Copy, PartialEq, Eq)]
        $vis enum $name {
            $($variant = $value),*
        }

        impl $name {

            pub fn from_u16(value: u16) -> Option<Self> {
                match value {
                    $($value => Some(Self::$variant),)*
                    _ => None
                }
            }

            pub fn from_u32(value: u32) -> Option<Self> {
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

        // impl fmt::Display for $name {
        //     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //         let name = match self {
        //             $(Self::$variant => stringify!($variant),)*
        //         };
        //         write!(f, "{}({})", name, self.to_u16())
        //     }
        // }
    }
}
    
define_enum_macro! {
    #[derive(Debug)]
    pub enum ContentType {
        change_cipher_spec = 20,
        alert = 21,
        handshake = 22,
        application_data = 23,
    }
}

define_enum_macro! {
    #[derive(Debug)]
    pub enum CipherSuite {
        // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
        // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
        // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
        // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
        // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023,
        // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027,
        TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x9c,
        // TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x3c,
        // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
        // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024,
        // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
        // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028,
        // TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x9d,
        // TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x3d
    }
}

define_enum_macro!(
    #[derive(Debug)]
    pub enum CompressionMethod {
        null = 0,
    }
);

#[derive(Debug, PartialEq, Eq)]
struct ChangeCipherSpec {
}

impl ChangeCipherSpec {
    pub fn new() -> Self {
        Self {}
    }

    pub fn to_vec(&self) -> Vec<u8> {
        vec![0x01]
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Alert {

}

impl Alert {
    pub fn new() -> Self {
        Self {}
    }
}


#[derive(Debug, PartialEq, Eq)]
struct ApplicationData {

}

impl ApplicationData {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TLSFragment {
    ChangeCipherSpec(ChangeCipherSpec),
    Alert(Alert),
    Handshake(Handshake),
    ApplicationData(ApplicationData),
}

impl TLSFragment {
    pub fn to_vec(&mut self) -> Vec<u8> {
        match self {
            TLSFragment::ChangeCipherSpec(change_cipher_spec) => change_cipher_spec.to_vec(),
            // TLSFragment::Alert(alert) => alert.to_vec(),
            TLSFragment::Handshake(handshake) => handshake.to_vec(),
            // TLSFragment::ApplicationData(application_data) => application_data.to_vec(),
            _ => panic!("Unsupported fragment type: {:?}", self)
        }
    }

    pub fn from_vec(content_type: ContentType, vec: Vec<u8>) -> Self {
        match content_type {
            ContentType::handshake => TLSFragment::Handshake(Handshake::from_vec(vec)),
            ContentType::change_cipher_spec => TLSFragment::ChangeCipherSpec(ChangeCipherSpec::new()),
            ContentType::alert => TLSFragment::Alert(Alert::new()),
            ContentType::application_data => TLSFragment::ApplicationData(ApplicationData::new()),
        }
    }
}

#[derive(Debug)]
pub struct TLSPlaintext {
    content_type: ContentType,
    version: ProtocolVersion,
    pub length: u16,
    pub fragment: TLSFragment,
}

impl TLSPlaintext {
    pub fn new(content_type: u8, version: ProtocolVersion) -> Self {
        let contentType = ContentType::from_u16(content_type as u16).unwrap();

        let fragment =  match contentType {
            ContentType::alert => { TLSFragment::Alert(Alert::new()) }
            ContentType::handshake => { TLSFragment::Handshake(Handshake::new(1)) }
            ContentType::application_data => { TLSFragment::ApplicationData(ApplicationData::new()) }
            ContentType::change_cipher_spec => { TLSFragment::ChangeCipherSpec(ChangeCipherSpec::new()) }
            _ => { panic!("Unsupported content type: {:?}", contentType) }
        };

        Self { 
            content_type: contentType, 
            version, 
            length: 0, 
            fragment 
        }
    }

    pub fn new_handshake_client_key_exchange(version: ProtocolVersion, key: Vec<u8>) -> Self {
        let mut fragment = ClientKeyExchange::from_key(key);
        let mut handshake = Handshake::new(16);
        handshake.fragment = HandshakeFragment::ClientKeyExchange(fragment);
        Self { 
            content_type: ContentType::handshake, 
            version, 
            length: 0, 
            fragment: TLSFragment::Handshake(handshake)
        }
    }

    pub fn new_change_cipher_spec() -> Self {
        Self {
            content_type: ContentType::change_cipher_spec,
            version: ProtocolVersion::new(3, 3),
            length: 0,
            fragment: TLSFragment::ChangeCipherSpec(ChangeCipherSpec::new()),
        }
    }

    pub fn new_handshake_finished(version: ProtocolVersion, verify_data: Vec<u8>) -> Self {
        let fragment = Finished::new(verify_data);
        let mut handshake = Handshake::new(20);
        handshake.fragment = HandshakeFragment::Finished(fragment);
        Self { 
            content_type: ContentType::handshake, 
            version, 
            length: handshake.to_vec().len() as u16, 
            fragment: TLSFragment::Handshake(handshake)
        }
    }

    pub fn new_handshake_data(version: ProtocolVersion, data: Vec<u8>) -> Self {
        let mut handshake = Handshake::new(255);
        handshake.fragment = HandshakeFragment::Unknown(data);
        Self { 
            content_type: ContentType::handshake, 
            version, 
            length: handshake.to_vec().len() as u16,    
            fragment: TLSFragment::Handshake(handshake)
        }
    }

    pub fn to_vec(&mut self) -> Vec<u8> {
        self.length = self.fragment.to_vec().len() as u16;

        let mut vec: Vec<u8> = Vec::new();
        vec.extend([self.content_type.to_vec()[1]]);
        vec.extend(self.version.to_vec());

        vec.extend(u16::to_be_bytes(self.length));
        vec.extend(self.fragment.to_vec());
        vec
    }

    pub fn from_vec(vec: Vec<u8>) -> Self { 
        let content_type = ContentType::from_u16(u16::from_be_bytes([0, vec[0]])).unwrap();
        let version = ProtocolVersion::new(vec[1], vec[2]);
        let length = u16::from_be_bytes([vec[3], vec[4]]);
        let fragment = TLSFragment::from_vec(content_type, vec[5..].to_vec());
        Self {
            content_type,
            version,
            length,
            fragment,
        }
    }
}

pub trait usizeToVec {
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