extern crate hex;

use std::net::Ipv6Addr;
use rust_sodium::crypto::hash::sha512;

use hex::FromHex as VecFromHex;
use hex::ToHex as VecToHex;
pub use cryptography::crypto_box;

pub const PUBLIC_KEY_BYTES: usize = crypto_box::PUBLICKEYBYTES;
pub const SECRET_KEY_BYTES: usize = crypto_box::SECRETKEYBYTES;

/// Used to decode a CryptoAuth public key.
///
/// # Example
///
/// ```
/// use fcp_cryptoauth::cryptography::crypto_box::PublicKey;
/// use fcp_cryptoauth::keys::FromBase32;
/// let pk = PublicKey::from_base32(b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k");
/// assert!(pk.is_some());
/// ```
pub trait FromBase32: Sized {
    // decode a base32-encoded byte array into an other byte array
    // Returns Err(c) if a character c is not valid in a Base32 string.
    fn from_base32(characters: &[u8]) -> Option<Self>;
}

/// Used to encode a CryptoAuth public key.
///
/// # Example
///
/// ```
/// use fcp_cryptoauth::cryptography::crypto_box::PublicKey;
/// use fcp_cryptoauth::keys::FromBase32;
/// use fcp_cryptoauth::keys::ToBase32;
/// let representation = b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k";
/// let pk = PublicKey::from_base32(representation).unwrap();
/// assert_eq!(pk.to_base32(), String::from_utf8(representation.to_vec()).unwrap());
/// ```
pub trait ToBase32: Sized {
    // encode a byte array into an other base32-encoded byte array
    fn to_base32(&self) -> String;
}

/// Used to decode a CryptoAuth secret key.
///
/// # Example
///
/// ```
/// use fcp_cryptoauth::cryptography::crypto_box::SecretKey;
/// use fcp_cryptoauth::keys::FromHex;
/// let sk = SecretKey::from_hex(b"ac3e53b518e68449692b0b2f2926ef2fdc1eac5b9dbd10a48114263b8c8ed12e");
/// assert!(sk.is_some());
/// ```
pub trait FromHex: Sized {
    fn from_hex(characters: &[u8]) -> Option<Self>;
}

/// Used to encode a CryptoAuth secret key.
///
/// # Example
///
/// ```
/// use fcp_cryptoauth::cryptography::crypto_box::SecretKey;
/// use fcp_cryptoauth::keys::FromHex;
/// use fcp_cryptoauth::keys::ToHex;
/// let representation = b"ac3e53b518e68449692b0b2f2926ef2fdc1eac5b9dbd10a48114263b8c8ed12e";
/// let sk = SecretKey::from_hex(representation).unwrap();
/// assert_eq!(sk.to_hex(), String::from_utf8(representation.to_vec()).unwrap());
/// ```
pub trait ToHex: Sized {
    fn to_hex(&self) -> String;
}

// DNSCurve's Base32 decoding table
const BASE32_DECODING_TABLE: [u8; 128] = [
        99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
        99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
        99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9,99,99,99,99,99,99,
        99,99,10,11,12,99,13,14,15,99,16,17,18,19,20,99,
        21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99,
        99,99,10,11,12,99,13,14,15,99,16,17,18,19,20,99,
        21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99
        ];
pub fn decode_base32(encoded: &[u8]) -> Result<Vec<u8>, u8> {
    let mut res = Vec::with_capacity(encoded.len()*5/8);
    let mut last_word_length = 0;
    let mut last_word = 0u16;
    for c in encoded.iter() {
        let c = c.clone();
        if c >= 128 {
            return Err(c);
        }
        let bits = BASE32_DECODING_TABLE[c as usize];
        if bits == 99 {
            return Err(c);
        }

        // Add the new bits at the left of the current word
        last_word += (bits as u16) << last_word_length;
        last_word_length += 5;

        // If the right byte of the current word is full, push the on the vector
        // and shift the current word to remove the right byte.
        if last_word_length >= 8 {
            last_word_length -= 8;
            res.push((last_word & 0b11111111) as u8);
            last_word >>= 8;
        }
    }
    if last_word > 0 {
        res.push(last_word as u8);
    }
    Ok(res)
}

#[test]
fn test_decode_base32() {
    assert_eq!(decode_base32(b"4321"), Ok(vec![0x64, 0x88]));
    decode_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050").unwrap();
}

impl FromBase32 for crypto_box::PublicKey {
    /// Returns a Public key from its Base32 representation.
    ///
    /// TODO: better errors
    fn from_base32(characters: &[u8]) -> Option<crypto_box::PublicKey> {
        assert!(characters.len() >= 2);
        let length: usize = characters.len()-2;
        assert_eq!(characters[length..], b".k".to_owned());
        if let Ok(bytes) = decode_base32(&characters[..length]) {
            crypto_box::PublicKey::from_slice(&bytes)
        }
        else {
            None
        }
    }
}

const BASE32_ENCODING_TABLE: [u8; 32] = [
        '0' as u8, '1' as u8, '2' as u8, '3' as u8, '4' as u8,
        '5' as u8, '6' as u8, '7' as u8, '8' as u8, '9' as u8,
        'b' as u8, 'c' as u8, 'd' as u8, 'f' as u8, 'g' as u8,
        'h' as u8, 'j' as u8, 'k' as u8, 'l' as u8, 'm' as u8,
        'n' as u8, 'p' as u8, 'q' as u8, 'r' as u8, 's' as u8,
        't' as u8, 'u' as u8, 'v' as u8, 'w' as u8, 'x' as u8,
        'y' as u8, 'z' as u8];
pub fn encode_base32(bytes: &[u8]) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();
    encoded.reserve(bytes.len()*8/5);
    let mut window = 0u16;
    let mut bits_in_window = 0;
    let mut bytes_offset = 0;
    assert!(BASE32_ENCODING_TABLE.len() == 32);
    while bytes_offset < bytes.len() || window > 0 {
        if bits_in_window < 5 {
            let byte = *bytes.get(bytes_offset).unwrap_or(&0);
            bytes_offset += 1;
            window += (byte as u16) << bits_in_window;
            bits_in_window += 8;
        }
        let char_index = (window & 0b11111) as usize;
        window >>= 5;
        bits_in_window -= 5;
        encoded.push(BASE32_ENCODING_TABLE[char_index]);
    }
    encoded
}

#[test]
fn test_encode_decode_base32() {
    let key = b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050";
    let expected = "2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb05";
    assert_eq!(String::from_utf8(encode_base32(&decode_base32(key).unwrap())).unwrap(), expected)
}

#[test]
fn test_encode_base32() {
    assert_eq!(String::from_utf8(encode_base32(&vec![0x64, 0x88])).unwrap(), "4321");
}

impl ToBase32 for crypto_box::PublicKey {
    /// Returns the Base32 representation of a Public key
    ///
    /// TODO: better errors
    fn to_base32(&self) -> String {
        let mut repr = encode_base32(&self.0);
        assert!(repr.len() <= 52);
        repr.resize(52, '0' as u8);
        repr.push('.' as u8);
        repr.push('k' as u8);
        String::from_utf8(repr).unwrap()
    }
}

/// Converts a public key to an Ipv6Addr, according to the first paragraph of
/// https://github.com/cjdelisle/cjdns/blob/cjdns-v19.1/doc/Whitepaper.md#pulling-it-all-together
///
/// # Example
///
/// ```
/// use std::net::Ipv6Addr;
/// use std::str::FromStr;
/// use fcp_cryptoauth::cryptography::crypto_box::PublicKey;
/// use fcp_cryptoauth::keys::{FromBase32, publickey_to_ipv6addr};
/// let pk = PublicKey::from_base32(b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k").unwrap();
/// let ip6 = Ipv6Addr::from_str("fc8f:a188:1b5:4de9:b0cb:5729:23a1:60f9").unwrap();
/// assert_eq!(publickey_to_ipv6addr(&pk), ip6);
/// ```
pub fn publickey_to_ipv6addr(pk: &crypto_box::PublicKey) -> Ipv6Addr {
    let digest1 = sha512::hash(&pk.0);
    let digest2 = sha512::hash(&digest1.0);
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&digest2.0[0..16]);
    Ipv6Addr::from(octets)
}

impl FromHex for crypto_box::SecretKey {
    fn from_hex(characters: &[u8]) -> Option<crypto_box::SecretKey> {
        let res = Vec::from_hex(characters);
        match res {
            Ok(vec) => {
                if vec.len() == 32 {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&vec);
                    crypto_box::SecretKey::from_slice(&bytes)
                }
                else {
                    None
                }
            },
            Err(_) => None,
        }
    }
}

impl ToHex for crypto_box::SecretKey {
    fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

#[test]
fn test_hex() {
    // Required for the result of SecretKey::to_hex() to always be
    // 64 characters.
    assert_eq!(vec![0, 0].to_hex(), "0000");
}
