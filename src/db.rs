use std::fmt::{self, write};
use crate::net;
use crate::rand;
use crate::hash::{self, hmac_sha256, VecStructU8};
use crate::handshake::{HandshakeType, Handshake, ClientKeyExchange, HandshakeFragment, Finished};
use std::io::{Read, Write};
use std::net::TcpStream;
use crate::crypto;
use crate::x509;
use crate::aes_crypto;
use std::io::{Error, ErrorKind};

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
    pub content_type: ContentType,
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
    ClientHello = 0x01,
    ServerHello = 0x02,
    Certificate = 0x0b,
    ClientKeyExchange = 0x16,
    Finished = 0x14,
}

impl Handshake_type {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ClientHello),
            2 => Some(Self::ServerHello),
            0x0b => Some(Self::Certificate),
            0x16 => Some(Self::ClientKeyExchange),
            0x14 => Some(Self::Finished),
            _ => None
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::ClientHello => 0x01,
            Self::ServerHello => 0x02,
            Self::Certificate => 0x0b,
            Self::ClientKeyExchange => 0x16,
            Self::Finished => 0x14,
        }
    }

    pub fn to_string(self) -> String {
        match self {
            Self::ClientHello => "ClientHello".to_string(),
            Self::ServerHello => "ServerHello".to_string(),
            Self::Certificate => "Certificate".to_string(),
            Self::ClientKeyExchange => "ClientKeyExchange".to_string(),
            Self::Finished => "Finished".to_string(),
        }
    }
}

pub struct HandshakeHash {
    pub data: Vec<u8>
}

impl HandshakeHash {
    fn new() -> Self{
        Self { data: vec![] }
    }

    pub fn update(&mut self, handshake_data: Vec<u8>) {
        self.data.extend(handshake_data);
    }

    // pub fn digest(&self, digest)
    pub fn digest(&self) -> Vec<u8> {
        hash::sha256(&self.data)
    }
}

pub struct TLSStreamManager {
    pub stream: TcpStream,
    pub handshake_hash: HandshakeHash,
    pub spec_change: u8,        // 0x01: client, 0x10: server
    pub security_parameters: SecurityParameters,
}

impl TLSStreamManager {
    pub fn new(server_url: &str) -> Self {
        let stream = TcpStream::connect(server_url).unwrap();
        let handshake_hash = HandshakeHash::new();
        Self{ stream, handshake_hash, spec_change: 0x00, security_parameters: SecurityParameters::new() }
    }
    
    // pub fn send(&mut self, tls_vec: &mut TLSPlaintext) -> Result<(), Error> {
    //     // if self.spec_change & 0x01 != 0 {
    //     //     let encrypted = self.encrypt(tls_vec.clone())?;
    //     //     let mut tls = TLSPlaintext::new_handshake_data(ProtocolVersion::new(3, 3), encrypted.clone());
    //     //     println!("tls: {:?}", tls.to_vec().hex_display());
    //     //     self.stream.write(&tls.to_vec())?;
    //     // // } else {
    //     self.stream.write(&tls_vec.to_vec())?;
    //     // }
    //     Ok(())
    // }

    pub fn send(&mut self, tls: &mut TLSPlaintext) -> Result<TLSPlaintext, Error> {
        if self.spec_change & 0x01 != 0 {
            let encrypted = self.encrypt(tls.fragment.to_vec())?;
            let mut tls = TLSPlaintext::new_handshake_data(ProtocolVersion::new(3, 3), encrypted.clone());
            self.stream.write(&tls.to_vec())?;
            Ok(tls)
        } else {
            panic!("spec_change is 0")
        }
    }

    pub fn send_handshake(&mut self, handshake_type: Handshake_type) -> Result<TLSPlaintext, Error> {
        let mut tls: TLSPlaintext;

        if handshake_type == Handshake_type::ClientHello {
            tls = TLSPlaintext::new(22, ProtocolVersion::new(3, 3));
            if let TLSFragment::Handshake(handshake) = &tls.fragment {
                if let HandshakeFragment::ClientHello(client_hello) = &handshake.fragment {
                    self.security_parameters.client_random = client_hello.random.to_vec();
                }
            }
        } else if handshake_type == Handshake_type::ClientKeyExchange {
            let mut pms: Vec<u8> = vec![0x03, 0x03];
            pms.extend(rand::rand_len(46));
            
            let mut seed: Vec<u8> = vec![];
            seed.extend(&self.security_parameters.client_random);
            seed.extend(&self.security_parameters.server_random);
    
            self.security_parameters.master_secret = crypto::prf(pms.clone(), b"master secret".to_vec(), seed, 48);
            
            let mut seed: Vec<u8> = self.security_parameters.server_random.to_vec();
            seed.extend(&self.security_parameters.client_random);

            let key_block_len: usize = 16 + 16 + 4 + 4;
            let key_block: Vec<u8> = crypto::prf(self.security_parameters.master_secret.clone(), b"key expansion".to_vec(), seed, key_block_len);
            self.security_parameters.client_write_key = key_block[0..16].to_vec();
            self.security_parameters.server_write_key = key_block[16..32].to_vec();
            self.security_parameters.client_write_iv = key_block[32..36].to_vec();
            self.security_parameters.server_write_iv = key_block[36..40].to_vec();

            println!("public_key: {:?}", self.security_parameters.public_key);
            let encrypted = crypto::RSA::encrypt(&pms, &self.security_parameters.public_key.n, &self.security_parameters.public_key.e);

            tls = TLSPlaintext::new_handshake_client_key_exchange(ProtocolVersion::new(3, 3), encrypted);
        } else if handshake_type == Handshake_type::Finished {
            let verify_data = crypto::prf(self.security_parameters.master_secret.clone(), b"client finished".to_vec(), self.handshake_hash.digest().to_vec(), 12);
            tls = TLSPlaintext::new_handshake_finished(ProtocolVersion::new(3, 3), verify_data);
        } else {
            panic!("Unsupported handshake type: {:?}", handshake_type);
        }

        if tls.content_type == ContentType::handshake {
            self.handshake_hash.update(tls.fragment.to_vec());
        }

        if self.spec_change & 0x01 != 0 {
            let encrypted = self.encrypt(tls.fragment.to_vec())?;
            tls = TLSPlaintext::new_handshake_data(ProtocolVersion::new(3, 3), encrypted.clone());
        }

        self.stream.write(&tls.to_vec())?;

        if tls.content_type == ContentType::change_cipher_spec {
            self.spec_change |= 0x01;
        }
        Ok(tls)
    }

    pub fn send_spec_change(&mut self) -> Result<TLSPlaintext, Error> {
        let mut tls = TLSPlaintext::new_change_cipher_spec();
        self.stream.write(&tls.to_vec())?;
        if tls.content_type == ContentType::change_cipher_spec {
            self.spec_change |= 0x01;
        }
        Ok(tls)
    }
    
    pub fn read(&mut self) -> Result<TLSPlaintext, Error> {
        // handshake 
        let mut buffer: Vec<u8> = [0 as u8; 5].to_vec();
        self.stream.read(&mut buffer)?;
        let handshake_len = u16::from_be_bytes([buffer[3], buffer[4]]);
        let mut handshake_buffer: Vec<u8> = vec![0 as u8; handshake_len as usize];
        self.stream.read(&mut handshake_buffer)?;
        buffer.extend(handshake_buffer);
        
        let mut tls: TLSPlaintext;

        if self.spec_change & 0x10 != 0 {
            tls = TLSPlaintext::new_handshake_data(ProtocolVersion::new(3, 3), buffer[5..].to_vec());
            if let TLSFragment::Handshake(handshake) = &tls.fragment {
                if let HandshakeFragment::Unknown(unknown) = &handshake.fragment {
                    let decrypted = self.decrypt(unknown.clone())?;
                    let handshake = Handshake::from_vec(decrypted);
                    tls.fragment = TLSFragment::Handshake(handshake);
                }
            }
        } else {
            tls = TLSPlaintext::from_vec(buffer);
        }
    

        if let TLSFragment::Handshake(handshake) = &tls.fragment {
            if let HandshakeFragment::ServerHello(server_hello) = &handshake.fragment {
                self.security_parameters.server_random = server_hello.random.to_vec();
            } else if let HandshakeFragment::Certificate(certificate) = &handshake.fragment {
                self.security_parameters.public_key = certificate.tbsCertificate[0].tbsCertificate.subject_public_key_info.publicKey.clone();
            }
        }

        if let TLSFragment::Handshake(handshake) = &tls.fragment {
            if let HandshakeFragment::Finished(finished) = &handshake.fragment {
                println!("handshake_hash: {:?}", self.handshake_hash.digest().to_vec().hex_display());
                let verify_data = crypto::prf(self.security_parameters.master_secret.clone(), b"server finished".to_vec(), self.handshake_hash.digest().to_vec(), 12);
                if finished.verify_data == verify_data {
                    println!("finished verified!: {:?}", finished.verify_data.hex_display());
                } else {
                    panic!("finished: {:?}", finished.verify_data.hex_display());
                }
            }
        }

        if tls.content_type == ContentType::handshake {
            self.handshake_hash.update(tls.fragment.to_vec());
            // println!("tls.fragment: {:?}", tls.fragment.to_vec().hex_display());
        }

        if tls.content_type == ContentType::change_cipher_spec {
            self.spec_change |= 0x10;
        }

        Ok(tls)
    }

    pub fn encrypt(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        // let aad = finished_tls.to_vec()[..5].to_vec();
        let mut nonce: Vec<u8> = self.security_parameters.client_write_iv.clone();
        // let explicit_nonce: Vec<u8> = rand::rand_len(8);
        let explicit_nonce: Vec<u8> = [0; 8].to_vec();
        nonce.extend(&explicit_nonce);
    
        let aes_gcm = aes_crypto::AES_GCM::new(self.security_parameters.client_write_key.clone());
    
        let mut aad: Vec<u8> = [0; 8].to_vec();
        aad.extend([0x16]);
        aad.extend([0x03, 0x03]);
        aad.extend([0x00, 0x10]);
        let encrypted = aes_gcm.encrypt(nonce.clone(), data.clone(), aad.clone());
    
        let mut encrypted_data: Vec<u8> = explicit_nonce;
        encrypted_data.extend(encrypted.clone());

        Ok(encrypted_data)
    }

    pub fn decrypt(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut nonce: Vec<u8> = self.security_parameters.server_write_iv.clone();
        nonce.extend(&data[..8]);

        let aes_gcm = aes_crypto::AES_GCM::new(self.security_parameters.server_write_key.clone());

        let mut aad: Vec<u8> = [0; 8].to_vec();
        aad.extend([0x16]);
        aad.extend([0x03, 0x03]);
        aad.extend([0x00, 0x10]);

        let decrypted = aes_gcm.decrypt(nonce.clone(), data[8..].to_vec(), aad.clone());

        Ok(decrypted)
    }
}

pub struct SecurityParameters {
    pub master_secret: Vec<u8>,
    pub client_random: Vec<u8>,
    pub server_random: Vec<u8>,
    pub public_key: x509::PublicKey,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

impl SecurityParameters {
    pub fn new() -> Self {
        Self {
            master_secret: vec![],
            client_random: vec![],
            server_random: vec![], 
            public_key: x509::PublicKey{ value: vec![], n: vec![], e: vec![] },
            client_write_key: vec![],
            server_write_key: vec![],
            client_write_iv: vec![],
            server_write_iv: vec![],
        }
    }
}