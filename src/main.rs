use std::io::prelude::*;
use std::net::TcpStream;

mod x509;
mod rand;
mod hash;
mod db;
mod handshake;
use crate::db::{TLSPlaintext, ProtocolVersion, CipherSuite, CompressionMethod, usizeToVec};
use crate::rand::rand;
use crate::hash::{VecStructU8, hmac_sha256};
mod net;

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

    Ok(())
}