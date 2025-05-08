// use std::io::prelude::*;
// use std::net::TcpStream;

mod db;

fn main() -> std::io::Result<()> {
    // let mut stream = TcpStream::connect("localhost:443")?;
    
    // stream.write_all(b"Hello, TLS client!")?;
    let cipher = db::CipherSuite::from_u16(0x1301);

    println!("{}", cipher.unwrap());
    let cipher = db::CipherSuite::to_u16(cipher.unwrap());

    println!("0x{:04X}", cipher);

    Ok(())
}