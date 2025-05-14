use std::io::{Read, Write};
use std::net::TcpStream;
use std::io::Error;
use crate::db::TLSPlaintext;
use crate::hash::VecStructU8;

pub fn write_tls(stream: &mut TcpStream, tls: &mut TLSPlaintext) -> Result<(), Error> {
    stream.write(&tls.to_vec())?;
    Ok(())
}

pub fn read_tls(stream: &mut TcpStream) -> Result<TLSPlaintext, Error> {
    // handshake 
    let mut buffer: Vec<u8> = [0 as u8; 5].to_vec();
    stream.read(&mut buffer)?;
    let handshake_len = u16::from_be_bytes([buffer[3], buffer[4]]);
    let mut handshake_buffer: Vec<u8> = vec![0 as u8; handshake_len as usize];
    stream.read(&mut handshake_buffer)?;
    buffer.extend(handshake_buffer);
    Ok(TLSPlaintext::from_vec(buffer))
}

