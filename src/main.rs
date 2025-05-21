use std::io::prelude::*;
use std::net::TcpStream;

mod x509;
mod rand;
mod hash;
mod db;
mod net;
mod handshake;
mod crypto;
mod bigint;
use crate::db::{TLSPlaintext, ProtocolVersion, CipherSuite, CompressionMethod, usizeToVec};
use crate::rand::{rand, rand_len};
use crate::hash::{VecStructU8, hmac_sha256};
use crate::crypto::RSA;
use crate::handshake::HandshakeFragment;
use crate::db::TLSFragment;

fn main() -> std::io::Result<()> {
    let mut tls = TLSPlaintext::new(22, ProtocolVersion::new(3, 1));
    let mut stream = TcpStream::connect("google.com:443")?;
    net::write_tls(&mut stream, &mut tls)?;
    println!("{:?}", tls);
    println!("--------------------------------");

    let tls = net::read_tls(&mut stream)?;
    println!("{:?}", tls);
    println!("--------------------------------");
    
    let tls = net::read_tls(&mut stream)?;
    println!("{:?}", tls);
    println!("--------------------------------");

    let mut encrypted: Vec<u8> = vec![];
    let mut pms: Vec<u8> = vec![3; 3];
    pms.extend(rand_len(46));
    if let TLSFragment::Handshake(handshake) = &tls.fragment {
        if let HandshakeFragment::Certificate(cert) = &handshake.fragment {
            let public_key = &cert.tbsCertificate[0].tbsCertificate.subject_public_key_info.publicKey;
            encrypted = RSA::encrypt(&pms, &public_key.n, &public_key.e);
        }
    }

    let mut tls = TLSPlaintext::new_handshake_client_key_exchange(ProtocolVersion::new(3, 3), encrypted);
    net::write_tls(&mut stream, &mut tls)?;
    println!("{:?}", tls);
    println!("--------------------------------");

    let tls = net::read_tls(&mut stream)?;
    println!("{:?}", tls);
    println!("--------------------------------");

    // TODO: ChangeCipherSpec
    // TODO: Finished


    Ok(())
}