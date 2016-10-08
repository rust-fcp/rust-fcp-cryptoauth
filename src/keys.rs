extern crate rust_sodium;
use rust_sodium::crypto::box_::curve25519xsalsa20poly1305 as crypto_box;

pub const PUBLIC_KEY_BYTES: usize = crypto_box::PUBLICKEYBYTES;
pub const SECRET_KEY_BYTES: usize = crypto_box::SECRETKEYBYTES;

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
// decode a base32-encoded byte array into an u32.
// Panics if the array is too large.
// Returns Err(c) if a character c is not valid in a Base32 string.
fn decode_base32(encoded: &[u8]) -> Result<Vec<u8>, u8> {
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
    decode_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050");
}

/// Represents a CryptoAuth public key.
///
/// # Example
///
/// ```
/// # use fcp_cryptoauth::keys::*;
/// let key = PublicKey::new_from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k");
/// assert!(key.is_some());
/// ```
pub struct PublicKey {
    pub crypto_box_key: crypto_box::PublicKey,
}
impl PublicKey {
    pub fn new_from_bytes(bytes: &[u8; PUBLIC_KEY_BYTES]) -> PublicKey {
        PublicKey { crypto_box_key: crypto_box::PublicKey::from_slice(bytes).unwrap(), }
    }
    /// Returns a Public key from its Base32 representation.
    ///
    /// TODO: better errors
    pub fn new_from_base32(characters: &[u8]) -> Option<PublicKey> {
        assert!(characters.len() >= 2);
        let length: usize = characters.len()-2;
        assert_eq!(characters[length..], b".k".to_owned());
        if let Ok(bytes) = decode_base32(&characters[..length]) {
            if let Some(key) = crypto_box::PublicKey::from_slice(&bytes) {
                Some(PublicKey { crypto_box_key: key })
            }
            else {
                None
            }
        }
        else {
            None
        }
    }

    pub fn bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.crypto_box_key.0
    }
}

pub struct SecretKey {
    pub crypto_box_key: crypto_box::SecretKey,
}
impl SecretKey {
    pub fn new(bytes: &[u8; SECRET_KEY_BYTES]) -> SecretKey {
        SecretKey { crypto_box_key: crypto_box::SecretKey::from_slice(bytes).unwrap(), }
    }

    pub fn bytes(&self) -> &[u8; SECRET_KEY_BYTES] {
        &self.crypto_box_key.0
    }
}

pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let (cb_pk, cb_sk) = crypto_box::gen_keypair();
    (PublicKey { crypto_box_key: cb_pk }, SecretKey { crypto_box_key: cb_sk })
}
