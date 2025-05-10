// use std::io::prelude::*;
// use std::net::TcpStream;

mod db;
mod rand;
mod hash;
use hash::sha256;
use hash::{VecStructU8, hmac_sha256};

fn main() -> std::io::Result<()> {

    // let tls = db::TLS::new();
    let value = hmac_sha256(vec![0x61], vec![0x62]);
    println!("{:?}", value.hex_display());
    Ok(())
}