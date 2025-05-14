use std::fmt::{self, write};
use crate::rand::rand;
use crate::hash::{VecStructU8, hmac_sha256};
use crate::handshake::{HandshakeType, Handshake};

#[derive(Debug)]
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
    }
}

define_enum_macro!(
    #[derive(Debug)]
    pub enum CompressionMethod {
        null = 0,
    }
);

#[derive(Debug)]
struct ChangeCipherSpec {

}

impl ChangeCipherSpec {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug)]
struct Alert {

}

impl Alert {
    pub fn new() -> Self {
        Self {}
    }
}


#[derive(Debug)]
struct ApplicationData {

}

impl ApplicationData {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug)]
enum TLSFragment {
    ChangeCipherSpec(ChangeCipherSpec),
    Alert(Alert),
    Handshake(Handshake),
    ApplicationData(ApplicationData),
}

impl TLSFragment {
    pub fn to_vec(&mut self) -> Vec<u8> {
        match self {
            // TLSFragment::ChangeCipherSpec(change_cipher_spec) => change_cipher_spec.to_vec(),
            // TLSFragment::Alert(alert) => alert.to_vec(),
            TLSFragment::Handshake(handshake) => handshake.to_vec(),
            // TLSFragment::ApplicationData(application_data) => application_data.to_vec(),
            _ => panic!("Unsupported fragment type: {:?}", self)
        }
    }

    pub fn from_vec(vec: Vec<u8>, fragment_type: Handshake_type) -> Self {
        match fragment_type {
            Handshake_type::ClientHello => TLSFragment::Handshake(Handshake::from_vec(vec)),
            _ => panic!("Unsupported fragment type: {:?}", fragment_type)
        }
    }
}

#[derive(Debug)]
pub struct TLSPlaintext {
    content_type: ContentType,
    version: ProtocolVersion,
    pub length: u16,
    fragment: TLSFragment,
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
        let fragment = TLSFragment::from_vec(vec[5..].to_vec(), Handshake_type::ClientHello);
        Self {
            content_type,
            version,
            length,
            fragment,
        }
    }
}
pub struct TlsHandshakeProtocol {
    handshake_type: Handshake_type,
    version: u16,
    pub random: Option<[u8; 32]>,
    session_id: Option<[u8; 32]>,
    cipher_suites: Option<Vec<CipherSuite>>,
    chosen_cipher: Option<CipherSuite>,
    certificate: Option<Vec<Certificate>>,
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
                let cipher_suite: CipherSuite = CipherSuite::from_u16(u16::from_be_bytes([vec[(39 + session_id_len) as usize], vec[(39 + session_id_len + 1) as usize]])).unwrap();
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
                let mut certificate_list: Vec<Certificate> = Vec::new();
                while offset < certificate_list_len + 7 {
                    let certificate_len = u32::from_be_bytes([0, vec[offset], vec[offset + 1], vec[offset + 2]]) as usize;
                    offset += 3;
                    let certificate = vec[offset..offset+certificate_len].to_vec();
                    offset += certificate_len;
                    certificate_list.push(Certificate::from_vec(certificate));
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

struct Certificate {
    length: u32,
    tbsCertificate: TBSCertificate,
}

impl Certificate {
    pub fn from_vec(vec: Vec<u8>) -> Self {
        let (Certificate_length, data) = Vec::<u8>::parseLength(vec);

        // ASN.1 tag
        let tbsCertificate = TBSCertificate::from_vec(data);

        Self {
            length: Certificate_length,
            tbsCertificate: tbsCertificate,
        }
    } 
}

trait VecCertificateSequence {
    fn parseLength(vec: Vec<u8>) -> (u32, Vec<u8>);
}

impl VecCertificateSequence for Vec<u8> {
    fn parseLength(vec: Vec<u8>) -> (u32, Vec<u8>) {
        let len_byte: u8 = vec[1];
        let len_bytes: u32;

        if (len_byte & 0x80) == 0 {
            len_bytes = u32::from_be_bytes([0, 0, 0, len_byte]);
        } else {
            let mut length_bytes: Vec<u8> = vec[2..(len_byte ^ 0x80) as usize + 2].to_vec();
            for _ in 0..4 - length_bytes.len() {
                length_bytes.insert(0, 0);
            }
            len_bytes = u32::from_be_bytes([length_bytes[0], length_bytes[1], length_bytes[2], length_bytes[3]]);
        }
        (len_bytes, vec[(len_byte ^ 0x80) as usize + 2..].to_vec())
    }
}

struct TBSCertificate {
    version: u8,
    serial_number: Vec<u8>,
    signature: u32,
    issuer: Option<Vec<u8>>,
    validity: Option<Vec<u8>>,
    subject: Option<Vec<u8>>,
    subject_public_key_info: Option<Vec<u8>>,
}

impl TBSCertificate {
    pub fn from_vec(vec: Vec<u8>) -> Self {
        let version: u8;
        let serial_number: u8;
        
        let (_, mut data) = Vec::<u8>::parseLength(vec);

        let tag = data[0];
        println!("tag: {}", tag);
        match tag {
            0xa0 => {
                let length = data[1];

                let value = data[2..(length as usize)+2].to_vec();
                serial_number = value[0];

                if value[1] == 1 {
                    version = value[2];
                } else {
                    panic!("Unsupported serial number length: {}", value[1]);
                }
                data = data[5..].to_vec();
            }
            _ => panic!("Unsupported tag: {}", tag)
        }

        // serial_number
        let serial_number_bytes: Vec<u8> = data[2..data[1] as usize + 2].to_vec();

        println!("version: {}", version);
        println!("serial_number_bytes: {:?}", serial_number_bytes.hex_display());
        data = data[serial_number_bytes.len() + 2..].to_vec();
        // println!("data: {:?}", data.hex_display());

        Self {
            version: version,
            serial_number: serial_number_bytes,
            signature: 0,
            issuer: None,
            validity: None,
            subject: None,
            subject_public_key_info: None,
        }
    }
}