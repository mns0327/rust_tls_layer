use std::io::prelude::*;
use std::net::TcpStream;

mod x509;
mod rand;
mod hash;
mod db;
mod net;
mod handshake;
mod crypto;
mod block_cipher;
mod bigint;
mod aes_crypto;
use crate::db::{TLSPlaintext, ProtocolVersion, CipherSuite, CompressionMethod, usizeToVec};
use crate::rand::{rand, rand_len};
use crate::hash::{VecStructU8, hmac_sha256};
use crate::crypto::RSA;
use crate::handshake::HandshakeFragment;
use crate::db::TLSFragment;

fn main() -> std::io::Result<()> {
    let mut client_random: [u8; 32] = [0; 32];
    let mut server_random: [u8; 32] = [0; 32];
    let mut client_hello_tls = TLSPlaintext::new(22, ProtocolVersion::new(3, 1));
    let mut stream = TcpStream::connect("google.com:443")?;
    
    net::write_tls(&mut stream, &mut client_hello_tls)?;  // client hello
    if let TLSFragment::Handshake(handshake) = &client_hello_tls.fragment {
        if let HandshakeFragment::ClientHello(client_hello) = &handshake.fragment {
            client_random = client_hello.random;
        }
    }
    println!("{:?}", client_hello_tls);
    println!("--------------------------------");

    let mut server_hello_tls = net::read_tls(&mut stream)?;  // server hello
    if let TLSFragment::Handshake(handshake) = &server_hello_tls.fragment {
        if let HandshakeFragment::ServerHello(server_hello) = &handshake.fragment {
            server_random = server_hello.random;
        }
    }
    println!("{:?}", server_hello_tls);
    println!("--------------------------------");
    
    let mut certificate_tls = net::read_tls(&mut stream)?;  // certificate
    println!("{:?}", certificate_tls);
    println!("--------------------------------");

    let mut server_hello_done_tls = net::read_tls(&mut stream)?;
    println!("{:?}", server_hello_done_tls);
    println!("{:?}", server_hello_done_tls.to_vec().hex_display());
    println!("--------------------------------");

    let mut encrypted: Vec<u8> = vec![];
    let mut pms: Vec<u8> = vec![3; 3];
    pms.extend(rand_len(46));
    if let TLSFragment::Handshake(handshake) = &certificate_tls.fragment {
        if let HandshakeFragment::Certificate(cert) = &handshake.fragment {
            let public_key = &cert.tbsCertificate[0].tbsCertificate.subject_public_key_info.publicKey;
            encrypted = RSA::encrypt(&pms, &public_key.n, &public_key.e);
        }
    }

    let mut client_key_exchange_tls = TLSPlaintext::new_handshake_client_key_exchange(ProtocolVersion::new(3, 3), encrypted);
    net::write_tls(&mut stream, &mut client_key_exchange_tls)?;  // client key exchange
    println!("{:?}", client_key_exchange_tls);
    println!("--------------------------------");

    let mut change_cipher_spec_tls = TLSPlaintext::new_change_cipher_spec();
    net::write_tls(&mut stream, &mut change_cipher_spec_tls)?;
    println!("{:?}", change_cipher_spec_tls);
    println!("--------------------------------");

    // TODO: Finished
    //verify_data = PRF(master_secret, "client finished", Hash(all_handshake_messages))[:12]

    // TODO: tls manager struct 
    let mut premaster_secret: Vec<u8> = vec![0x03, 0x03, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11];
    let client_random: Vec<u8> = vec![0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa];
    let server_random: Vec<u8> = vec![0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb];

    let mut seed: Vec<u8> = vec![];
    seed.extend(&client_random);
    seed.extend(&server_random);

    let master_secret = crypto::prf(premaster_secret, b"master secret".to_vec(), seed, 48);

    println!("{:?}", master_secret.hex_display());

    let mut seed: Vec<u8> = vec![];
    seed.extend(&server_random);
    seed.extend(&client_random);

    let key_block_len: usize = 20 + 20 + 16 + 16 + 16 + 16;

    let mut key_block: Vec<u8> = crypto::prf(master_secret.clone(), b"key expansion".to_vec(), seed, key_block_len);

    let client_master_key = key_block[0..20].to_vec();
    let server_master_key = key_block[20..40].to_vec();
    let client_write_key = key_block[40..56].to_vec();
    let server_write_key = key_block[56..72].to_vec();
    let client_write_iv = key_block[72..88].to_vec();
    let server_write_iv = key_block[88..104].to_vec();
    
    // println!("{:?}", client_master_key.hex_display());
    // println!("{:?}", server_master_key.hex_display());
    // println!("{:?}", client_write_key.hex_display());
    // println!("{:?}", server_write_key.hex_display());
    // println!("{:?}", client_write_iv.hex_display());
    // println!("{:?}", server_write_iv.hex_display());

    let mut handshake_message: Vec<u8> = vec![];
    handshake_message.extend(&client_hello_tls.to_vec());
    handshake_message.extend(&server_hello_tls.to_vec());
    handshake_message.extend(&certificate_tls.to_vec());
    handshake_message.extend(&server_hello_done_tls.to_vec());
    handshake_message.extend(&client_key_exchange_tls.to_vec());

    let handshake_hash = hash::sha256(&handshake_message);

    let verify_data = crypto::prf(master_secret.clone(), b"client finished".to_vec(), handshake_hash.clone(), 12);

    println!("{:?}", verify_data.hex_display());

    let mut finished_tls = TLSPlaintext::new_handshake_finished(ProtocolVersion::new(3, 3), verify_data);

    println!("{:?}", finished_tls.to_vec().hex_display());
    println!("--------------------------------");

    let plaintext = b"hello world";
    let key = b"0123456789abcdef";
    let iv = b"";
    let encrypted = aes_crypto::aes_gcm_encrypt([0; 16].to_vec(), [0; 12].to_vec(), [0; 12].to_vec(), [0x16, 0x03, 0x03].to_vec());
    println!("encrypted: {:?}", encrypted.hex_display());

    Ok(())
}