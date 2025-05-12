use std::io::prelude::*;
use std::net::TcpStream;

mod db;
mod rand;
mod hash;
use rand::rand;
use hash::{VecStructU8, hmac_sha256};

fn main() -> std::io::Result<()> {

    let tls = db::TLS::new();

    println!("{}", tls);
    println!("--------------------------------");
    let mut stream = TcpStream::connect("google.com:443")?;

    let mut buffer: Vec<u8> = [0 as u8; 128].to_vec();

    stream.write(&tls.to_vec())?;
    stream.read(&mut buffer)?;
    println!("{}", buffer.hex_display());
    
    let tls = db::TLS::from_vec(buffer.to_vec());
    println!("--------------------------------");
    println!("{}", tls);
    Ok(())
}