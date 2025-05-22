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
    let mut client_random: [u8; 32] = [0; 32];
    let mut server_random: [u8; 32] = [0; 32];
    let mut tls = TLSPlaintext::new(22, ProtocolVersion::new(3, 1));
    let mut stream = TcpStream::connect("google.com:443")?;
    
    net::write_tls(&mut stream, &mut tls)?;  // client hello
    if let TLSFragment::Handshake(handshake) = &tls.fragment {
        if let HandshakeFragment::ClientHello(client_hello) = &handshake.fragment {
            client_random = client_hello.random;
        }
    }
    println!("{:?}", tls);
    println!("--------------------------------");

    let tls = net::read_tls(&mut stream)?;  // server hello
    if let TLSFragment::Handshake(handshake) = &tls.fragment {
        if let HandshakeFragment::ServerHello(server_hello) = &handshake.fragment {
            server_random = server_hello.random;
        }
    }
    println!("{:?}", tls);
    println!("--------------------------------");
    
    let tls = net::read_tls(&mut stream)?;  // certificate
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
    net::write_tls(&mut stream, &mut tls)?;  // client key exchange
    println!("{:?}", tls);
    println!("--------------------------------");

    let tls = net::read_tls(&mut stream)?;
    println!("{:?}", tls);
    println!("--------------------------------");

    let mut tls = TLSPlaintext::new_change_cipher_spec();
    net::write_tls(&mut stream, &mut tls)?;
    println!("{:?}", tls);
    println!("--------------------------------");

    // TODO: Finished
    //verify_data = PRF(master_secret, "client finished", Hash(all_handshake_messages))[:12]

    // TODO: tls manager struct 

    Ok(())
}