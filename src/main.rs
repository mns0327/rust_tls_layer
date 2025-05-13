use std::io::prelude::*;
use std::net::TcpStream;

mod db;
mod rand;
mod hash;
use crate::rand::rand;
use crate::hash::{VecStructU8, hmac_sha256};
mod net;

fn main() -> std::io::Result<()> {

    let tls = db::TLS::new();

    println!("{}", tls);
    println!("--------------------------------");
    let mut stream = TcpStream::connect("google.com:443")?;

    stream.write(&tls.to_vec())?;
    let tls = net::read_tls(&mut stream)?;

    println!("{}", tls);
    println!("--------------------------------");

    let tls = net::read_tls(&mut stream)?;

    println!("{}", tls);
    println!("--------------------------------");
    Ok(())
}