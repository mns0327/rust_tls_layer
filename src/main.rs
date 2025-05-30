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

    let mut steam_manager = db::TLSStreamManager::new("localhost:4433");
    let mut client_hello_tls = steam_manager.send_handshake(db::Handshake_type::ClientHello)?;  // client hello
    println!("{:?}", client_hello_tls);
    println!("--------------------------------");

    let mut server_hello_tls = steam_manager.read()?;  // server hello
    println!("{:?}", server_hello_tls);
    println!("--------------------------------");
    
    let mut certificate_tls = steam_manager.read()?;  // certificate
    println!("{:?}", certificate_tls);
    println!("--------------------------------");

    let mut server_hello_done_tls = steam_manager.read()?;
    println!("{:?}", server_hello_done_tls);
    println!("{:?}", server_hello_done_tls.to_vec().hex_display());
    println!("--------------------------------");

    let mut client_key_exchange_tls = steam_manager.send_handshake(db::Handshake_type::ClientKeyExchange)?;  // client key exchange
    println!("{:?}", client_key_exchange_tls);
    println!("--------------------------------");

    let mut change_cipher_spec_tls = steam_manager.send_spec_change()?;
    println!("{:?}", change_cipher_spec_tls);
    println!("--------------------------------");
    
    let mut finished_tls = steam_manager.send_handshake(db::Handshake_type::Finished)?;
    println!("{:?}", finished_tls);
    println!("--------------------------------");
    
    let mut server_spec_change = steam_manager.read()?;
    println!("{:?}", server_spec_change);
    println!("--------------------------------");
    
    let mut server_finished_tls = steam_manager.read()?;
    println!("{:?}", server_finished_tls);
    println!("--------------------------------");

    Ok(())
}