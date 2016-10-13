extern crate hex;
use hex::FromHex as VecFromHex;
use cryptography::crypto_box;

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
