use std::io::prelude::*;
use std::net::TcpStream;

mod db;
mod rand;
mod hash;
use rand::rand;
use hash::{VecStructU8, hmac_sha256};

fn main() -> std::io::Result<()> {

    let tls = db::TLS::new();

    // let value = rand().to_vec();
    println!("{:?}", tls.to_vec().hex_display());
    let mut stream = TcpStream::connect("google.com:443")?;

    let mut buffer: Vec<u8> = [0 as u8; 128].to_vec();

    stream.write(&tls.to_vec())?;
    stream.read(&mut buffer)?;
    println!("{}", buffer.hex_display());
    println!("{:?}", tls.handshake.random.to_vec().hex_display());
    Ok(())
}