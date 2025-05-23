use std::io::Error;
use std::fmt;
use crate::hash::VecStructU8;

pub fn wrap_with_sequence(tag: u8, vec_data: Vec<u8>) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::new();
    vec.extend([tag]);
    if vec_data.len() >= 0x80 {
        let data_len_bytes = u32::to_be_bytes(vec_data.len() as u32);   // TODO: length limit
        let mut len_size: u8 = 0;
        for i in 0..data_len_bytes.len() {
            if data_len_bytes[i] != 0 {
                len_size = 4 - (i as u8);
                break;
            }
        }
        vec.extend([0x80 | len_size]);
        vec.extend(&data_len_bytes[4-(len_size as usize)..]);
    } else {
        vec.extend([vec_data.len() as u8]);
    }
    vec.extend(vec_data);

    vec
}

pub fn wrap_name(name: Vec<name_struct>) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::new();
    for name in name {
        vec.extend(name.to_vec());
    }
    vec = wrap_with_sequence(0x30, vec);
    vec
}

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

#[derive(Debug, PartialEq, Eq)]
pub struct Certificate {
    pub tbsCertificate: TBSCertificate,
    pub signatureAlgorithm: AlgorithmIdentifier,
    pub signatureValue: Vec<u8>,
}

#[derive(PartialEq, Eq, Clone)]
pub struct oid_struct {
    pub data: Vec<u8>,
}

impl oid_struct {
    pub fn to_vec(&self) -> Vec<u8> {
        wrap_with_sequence(0x06, self.data.clone())
    }
}

impl fmt::Debug for oid_struct {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let first = self.data[0];
        let mut oid = vec![format!("{}", first / 40), format!("{}", first % 40)];
        let mut val = 0u32;
        for & b in &self.data[1..] {
            val = (val << 7) | (b as u32);
            if (b & 0x80) == 0 {
                oid.push(format!("{}", val));
                val = 0;
            }
        }
        write!(f, "{}", oid.join("."))
    }
}

#[derive(PartialEq, Eq, Clone)]
pub struct name_struct {
    pub oid: oid_struct,
    pub value: String,
    pub value_tag: u8,
}

impl fmt::Debug for name_struct {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}={}", self.oid, self.value)
    }
}

impl name_struct {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend(self.oid.to_vec());
        vec.extend(wrap_with_sequence(self.value_tag, self.value.as_bytes().to_vec()));
        vec = wrap_with_sequence(0x30, vec);
        vec = wrap_with_sequence(0x31, vec);
        vec
    }
}

#[derive(PartialEq, Eq, Clone)]
pub struct time_struct {
    pub value: Vec<u8>,
    pub time_tag: u8,
}

impl fmt::Debug for time_struct {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.time_tag {
            0x17 => {
                write!(f, "20{}-{}-{} {}:{}:{}Z", 
                    String::from_utf8_lossy(&self.value[0..2]),
                    String::from_utf8_lossy(&self.value[2..4]), 
                    String::from_utf8_lossy(&self.value[4..6]),
                    String::from_utf8_lossy(&self.value[6..8]),
                    String::from_utf8_lossy(&self.value[8..10]),
                    String::from_utf8_lossy(&self.value[10..12]))
            }
            0x18 => {
                write!(f, "{}-{}-{} {}:{}:{}Z", 
                    String::from_utf8_lossy(&self.value[0..4]),
                    String::from_utf8_lossy(&self.value[4..6]),
                    String::from_utf8_lossy(&self.value[6..8]),
                    String::from_utf8_lossy(&self.value[8..10]),
                    String::from_utf8_lossy(&self.value[10..12]),
                    String::from_utf8_lossy(&self.value[12..14]))
            }
            _ => {
                panic!("Expected time, got tag: {}", self.time_tag);
            }
        }
    }
}

impl time_struct {
    pub fn to_vec(&self) -> Vec<u8> {
        wrap_with_sequence(self.time_tag, self.value.clone())
    }
}

impl Certificate {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        
        vec.extend(self.tbsCertificate.to_vec());
        vec.extend(self.signatureAlgorithm.to_vec());

        let mut sig_bytes: Vec<u8> = vec![0];
        sig_bytes.extend(self.signatureValue.clone());
        vec.extend(wrap_with_sequence(0x03, sig_bytes));
        vec = wrap_with_sequence(0x30, vec);
        vec
    }

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

#[derive(Debug, PartialEq, Eq)]
pub struct TBSCertificate {
    version: u8,
    serialNumber: Vec<u8>,
    pub signature: AlgorithmIdentifier,
    pub issuer: Vec<name_struct>,
    pub validity: Validity,
    pub subject: Vec<name_struct>,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub issuerUniqueID: Option<Vec<u8>>,
    pub subjectUniqueID: Option<Vec<u8>>,
    pub extensions: Extensions,
}

impl TBSCertificate {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();

        if self.version == 2 {  // version
            let version = wrap_with_sequence(0x02, vec![0x02]);
            let version_bytes = wrap_with_sequence(0xA0, version);
            vec.extend(version_bytes);
        } else {
            panic!("Unsupported version: {}", self.version);    // TODO: support other versions
        }

        vec.extend(wrap_with_sequence(0x02, self.serialNumber.clone()));

        vec.extend(self.signature.to_vec());
        vec.extend(wrap_name(self.issuer.clone()));
        vec.extend(self.validity.to_vec());
        vec.extend(wrap_name(self.subject.clone()));
        vec.extend(self.subject_public_key_info.to_vec());

        // TODO: issuerUniqueID
        // TODO: subjectUniqueID
        vec.extend(self.extensions.to_vec());
        vec = wrap_with_sequence(0x30, vec);
        vec
    }
    
    pub fn parse_from_parser(parser: &mut ASN1Parser) -> Self {
        let mut tbs = parser.parse_sequence();
        let version = if tbs.data[tbs.offset] == 0xA0 {
            let (_, _, version_bytes) = tbs.read_tlv();
            let (_, _, version) = ASN1Parser::new(&version_bytes).read_tlv();
            version[0]
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

#[derive(Debug, PartialEq, Eq)]
struct AlgorithmIdentifier {
    algorithm: oid_struct,
    parameters: Option<Vec<u8>>,
}

impl AlgorithmIdentifier {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        let algorithm = self.algorithm.data.clone();
        vec.extend(wrap_with_sequence(0x06, algorithm));
        if let Some(params) = &self.parameters {
            vec.extend(wrap_with_sequence(params[0], params[1..].to_vec()));
        }
        vec = wrap_with_sequence(0x30, vec);
        vec
    }

    pub fn parse_from_parser(parser: &mut ASN1Parser) -> Self {
        let mut sig_alg = parser.parse_sequence();
        let (_, _, mut data) = sig_alg.read_tlv();
        let data = data.to_vec();
        let oid = oid_struct { data };

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

#[derive(Debug, PartialEq, Eq)]
struct Validity {
    notBefore: time_struct,
    notAfter: time_struct,
}

impl Validity {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend(self.notBefore.to_vec());
        vec.extend(self.notAfter.to_vec());
        vec = wrap_with_sequence(0x30, vec);
        vec
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Extensions {
    extensions: Vec<Extension>,
}

impl Extensions {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        for extension in self.extensions.clone() {
            let mut ext_vec: Vec<u8> = Vec::new();
            ext_vec.extend(extension.oid.to_vec());
            let critical_bytes = if extension.critical == 0xff {
                wrap_with_sequence(0x01, vec![extension.critical])
            } else {
                vec![]
            };
            ext_vec.extend(critical_bytes);
            ext_vec.extend(wrap_with_sequence(0x04, extension.value.clone()));
            ext_vec = wrap_with_sequence(0x30, ext_vec);
            vec.extend(ext_vec);
        }
        vec = wrap_with_sequence(0x30, vec);
        vec = wrap_with_sequence(0xA3, vec);
        vec
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub value: Vec<u8>,
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Extension {
    oid: oid_struct,
    critical: u8,
    value: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub publicKey: PublicKey,
}

impl SubjectPublicKeyInfo {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = vec![];

        vec.extend(self.algorithm.to_vec());
        vec.extend(wrap_with_sequence(0x03, self.publicKey.value.clone()));
        vec = wrap_with_sequence(0x30, vec);
        vec
    }

    pub fn parse_from_parser(parser: &mut ASN1Parser) -> Self {
        let mut seq = parser.parse_sequence();

        let algorithm = AlgorithmIdentifier::parse_from_parser(&mut seq);
        let (bit_str, unused_bits) = seq.parse_bit_string();
        
        let (n, e) = parse_public_key(&bit_str);
        
        let mut value: Vec<u8> = vec![unused_bits];
        value.extend(bit_str);

        Self {
            algorithm,
            publicKey: PublicKey { value, n, e },
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

    pub fn parse_oid(&mut self) -> oid_struct {
        let (tag, _, value) = self.read_tlv();
        if tag != 0x06 {
            panic!("Expected OID, got tag: {}", tag);
        }
        
        oid_struct { data: value.to_vec() }
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

    pub fn parse_name(&mut self) -> Vec<name_struct> {
        let mut name_seq = self.parse_sequence();
        // self.offset += length;
        let mut parts = vec![];

        while name_seq.offset < name_seq.data.len() {
            let mut rdn_set = name_seq.parse_set();
            let mut atv_seq = rdn_set.parse_sequence();
            let (_, _, oid) = atv_seq.read_tlv();
            let (value_tag, _, value) = atv_seq.read_tlv();
            let value = String::from_utf8_lossy(value).into_owned();
            parts.push(name_struct { oid: oid_struct { data: oid.to_vec() }, value, value_tag });
        }

        parts
    }

    fn parse_time(&mut self) -> time_struct {
        let (tag, _, value) = self.read_tlv();
        let s = String::from_utf8_lossy(value).into_owned();
        time_struct { value: value.to_vec(), time_tag: tag }
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
                let (tag, _, val) = ext_seq.read_tlv();
                val[0]
            } else {
                0
            };

            let (tag, _, value) = ext_seq.read_tlv();
            extensions.push(Extension { oid, critical, value: value.to_vec() });
        }

        Extensions { extensions }
    }
}