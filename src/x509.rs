use std::io::Error;
use std::fmt;
use crate::hash::VecStructU8;

pub trait VecCertificateSequence {
    fn parseLength(&self) -> (u32, Vec<u8>);
}

impl VecCertificateSequence for Vec<u8> {
    fn parseLength(&self) -> (u32, Vec<u8>) {
        let len_byte: u8 = self[1];
        let len_bytes: u32;

        if (len_byte & 0x80) == 0 {
            len_bytes = u32::from_be_bytes([0, 0, 0, len_byte]);
        } else {
            let mut length_bytes: Vec<u8> = self[2..(len_byte ^ 0x80) as usize + 2].to_vec();
            for _ in 0..4 - length_bytes.len() {
                length_bytes.insert(0, 0);
            }
            len_bytes = u32::from_be_bytes([length_bytes[0], length_bytes[1], length_bytes[2], length_bytes[3]]);
        }
        (len_bytes, self[(len_byte ^ 0x80) as usize + 2..].to_vec())
    }
}

#[derive(Debug)]
pub struct Certificate {
    pub tbsCertificate: TBSCertificate,
    pub signatureAlgorithm: AlgorithmIdentifier,
    pub signatureValue: Vec<u8>,
}

impl Certificate {
    pub fn from_vec(vec: Vec<u8>) -> Self {
        let mut parser = ASN1Parser::new(&vec);

        let mut cert_seq = parser.parse_sequence();

        let tbs = TBSCertificate::parse_from_parser(&mut cert_seq);
        let sig_alg = AlgorithmIdentifier::parse_from_parser(&mut cert_seq);
        let (sig_value, _) = cert_seq.parse_bit_string();

        Self {
            tbsCertificate: tbs,
            signatureAlgorithm: sig_alg,
            signatureValue: sig_value.to_vec(),
        }
    }
}

#[derive(Debug)]
pub struct TBSCertificate {
    version: u8,
    serialNumber: Vec<u8>,
    pub signature: AlgorithmIdentifier,
    pub issuer: String,
    pub validity: Validity,
    pub subject: String,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub issuerUniqueID: Option<Vec<u8>>,
    pub subjectUniqueID: Option<Vec<u8>>,
    pub extensions: Extensions,
}

impl TBSCertificate {
    pub fn parse_from_parser(parser: &mut ASN1Parser) -> Self {
        let mut tbs = parser.parse_sequence();

        let version = if tbs.data[tbs.offset] == 0xA0 {
            tbs.read_tlv();
            2
        } else {
            1
        };
        
        let (_, _, serial_bytes) = tbs.read_tlv();

        let sig_alg = AlgorithmIdentifier::parse_from_parser(&mut tbs);
        let issuer = tbs.parse_name();
        let validity = tbs.parse_validity();
        let subject = tbs.parse_name();
        let subject_public_key_info = SubjectPublicKeyInfo::parse_from_parser(&mut tbs);

        let extensions = tbs.parse_extensions();

        Self {
            version,
            serialNumber: serial_bytes.to_vec(),
            signature: sig_alg,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuerUniqueID: None,
            subjectUniqueID: None,
            extensions: extensions,
        }
    }
}

#[derive(Debug)]
struct AlgorithmIdentifier {
    algorithm: String,
    parameters: Option<Vec<u8>>,
}

impl AlgorithmIdentifier {
    pub fn parse_from_parser(parser: &mut ASN1Parser) -> Self {
        let mut sig_alg = parser.parse_sequence();
        let oid = sig_alg.parse_oid();

        let params = if sig_alg.offset < sig_alg.data.len() {
            let (tag, _, params) = sig_alg.read_tlv();
            Some([tag].iter().copied().chain(params.iter().copied()).collect())
        } else {
            None
        };

        Self {
            algorithm: oid,
            parameters: params,
        }
    }
}

#[derive(Debug)]
struct Validity {
    notBefore: String,
    notAfter: String,
}

#[derive(Debug)]
struct Extensions {
    extensions: Vec<Extension>,
}

#[derive(Debug)]
pub struct PublicKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

#[derive(Debug)]
struct Extension {
    oid: String,
    critical: bool,
    value: Vec<u8>,
}

#[derive(Debug)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub publicKey: PublicKey,
}

impl SubjectPublicKeyInfo {
    pub fn parse_from_parser(parser: &mut ASN1Parser) -> Self {
        let mut seq = parser.parse_sequence();

        let algorithm = AlgorithmIdentifier::parse_from_parser(&mut seq);
        let (bit_str, _) = seq.parse_bit_string();

        let (n, e) = parse_public_key(&bit_str);
        
        Self {
            algorithm,
            publicKey: PublicKey { n, e },
        }
    }
}

pub fn parse_public_key(publicKey: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut publicKey_seq = ASN1Parser::new(publicKey)
        .parse_sequence();
    

    let (_, _, n) = publicKey_seq.read_tlv();
    let (_, _, e) = publicKey_seq.read_tlv();

    (n[1..].to_vec(), e.to_vec())
}

pub struct ASN1Parser<'a> {
    pub data: &'a [u8],
    pub offset: usize,
}

impl<'a> ASN1Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_byte(&mut self) -> u8 {
        let byte = self.data[self.offset];
        self.offset += 1;
        byte
    }

    fn read_bytes(&mut self, length: usize) -> &'a [u8] {
        let bytes = &self.data[self.offset..self.offset + length];
        self.offset += length;
        bytes
    }

    fn read_length(&mut self) -> usize {
        let first = self.read_byte();
        if (first & 0x80) == 0 {
            first as usize
        } else {
            let num_bytes = first & 0x7F;
            let mut len = 0;
            for _ in 0..num_bytes {
                len = (len << 8) | self.read_byte() as usize;
            }
            len
        }
    }
    
    pub fn read_tlv(&mut self) -> (u8, usize, &'a [u8]) {
        let tag = self.read_byte();
        let length = self.read_length();
        let value = self.read_bytes(length);
        (tag, length, value)
    }
    
    pub fn parse_sequence(&mut self) -> ASN1Parser<'a> {
        let (tag, length, value) = self.read_tlv();
        if tag != 0x30 {
            panic!("Expected sequence, got tag: {}", tag);
        }
        ASN1Parser::new(value)
    }

    pub fn parse_oid(&mut self) -> String {
        let (tag, _, value) = self.read_tlv();
        if tag != 0x06 {
            panic!("Expected OID, got tag: {}", tag);
        }
        
        let first = value[0];
        let mut oid = vec![format!("{}", first / 40), format!("{}", first % 40)];
        let mut val = 0u32;
        for & b in &value[1..] {
            val = (val << 7) | (b as u32);
            if (b & 0x80) == 0 {
                oid.push(format!("{}", val));
                val = 0;
            }
        }
        oid.join(".")
    }

    pub fn parse_bit_string(&mut self) -> (&'a [u8], u8) {
        let (tag, _, value) = self.read_tlv();
        if tag != 0x03 {
            panic!("Expected bit string, got tag: {}", tag);
        }
        let unused_bits = value[0];
        (&value[1..], unused_bits)
    }

    pub fn parse_set(&mut self) -> ASN1Parser<'a> {
        let (tag, _, value) = self.read_tlv();
        if tag != 0x31 {
            panic!("Expected set, got tag: {}", tag);
        }
        ASN1Parser::new(value)
    }

    pub fn peek_byte(&self) -> u8 {
        self.data[self.offset]
    }

    pub fn parse_name(&mut self) -> String {
        let mut name_seq = self.parse_sequence();
        // self.offset += length;
        let mut parts = vec![];

        while name_seq.offset < name_seq.data.len() {
            let mut rdn_set = name_seq.parse_set();
            let mut atv_seq = rdn_set.parse_sequence();
            let oid = atv_seq.parse_oid();
            let (_, _, value) = atv_seq.read_tlv();
            let value = String::from_utf8_lossy(value).into_owned();
            parts.push(format!("{}={}", oid, value));
        }

        parts.join(", ")
    }

    fn parse_time(&mut self) -> String {
        let (tag, _, value) = self.read_tlv();
        let s = String::from_utf8_lossy(value).into_owned();
        match tag {
            0x17 => {
                format!("20{}-{}-{} {}:{}:{}Z", &s[0..2], &s[2..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12])
            }
            0x18 => {
                format!("{}-{}-{} {}:{}:{}Z", &s[0..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12], &s[12..14])
            }
            _ => {
                panic!("Expected time, got tag: {}", tag);
            }
        }
    }

    pub fn parse_validity(&mut self) -> Validity {
        let mut validity = self.parse_sequence();
        Validity {
            notBefore: validity.parse_time(),
            notAfter: validity.parse_time(),
        }
    }

    pub fn parse_extensions(&mut self) -> Extensions {
        let (tag, _, value) = self.read_tlv();
        if tag != 0xA3 {
            panic!("Expected extensions, got tag: {}", tag);
        }
        let mut ext_seq = ASN1Parser::new(value);
        let mut ext_container = ext_seq.parse_sequence();

        let mut extensions = vec![];
        while ext_container.offset < ext_container.data.len() {
            let mut ext_seq = ext_container.parse_sequence();
            let oid = ext_seq.parse_oid();

            let critical = if ext_seq.peek_byte() == 0x01 {
                let (_, _, val) = ext_seq.read_tlv();
                val == [0xff]
            } else {
                false
            };

            let (_, _, value) = ext_seq.read_tlv();
            extensions.push(Extension { oid, critical, value: value.to_vec() });
        }

        Extensions { extensions }
    }
}