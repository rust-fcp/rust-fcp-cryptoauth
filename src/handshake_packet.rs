//! Contains the `HandshakePacket` structure, and a `HandshakePacketBuilder` to
//! construct it field by field.
//!
//! # Example
//!
//! ```
//! use fcp_cryptoauth::handshake_packet::{HandshakePacketBuilder, HandshakePacket, HandshakePacketType};
//! let packet = HandshakePacketBuilder::new()
//!         .packet_type(&HandshakePacketType::Key)
//!         .auth_challenge(&[1u8; 12])
//!         .random_nonce(&[2u8; 24])
//!         .sender_perm_pub_key(&[3u8; 32])
//!         .msg_auth_code(&[4u8; 16])
//!         .sender_encrypted_temp_pub_key(&[5u8; 32])
//!         .encrypted_data(&vec![6u8, 7u8, 8u8])
//!         .finalize()
//!         .unwrap();
//! assert_eq!(packet.packet_type(), Ok(HandshakePacketType::Key));
//! assert_eq!(packet.auth_challenge(), [1u8; 12]);
//! assert_eq!(packet.random_nonce(), [2u8; 24]);
//! assert_eq!(packet.sender_perm_pub_key(), [3u8; 32]);
//! assert_eq!(packet.msg_auth_code(), [4u8; 16]);
//! assert_eq!(packet.sender_encrypted_temp_pub_key(), [5u8; 32]);
//! assert_eq!(packet.encrypted_data(), [6u8, 7u8, 8u8]);
//! assert_eq!(packet.raw, vec![
//!         // session state
//!         0, 0, 0, 2,
//!
//!         // auth challenge
//!                      1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,
//!
//!         // random nonce
//!         2, 2, 2, 2,  2, 2, 2, 2,  2, 2, 2, 2,  2, 2, 2, 2,
//!         2, 2, 2, 2,  2, 2, 2, 2,
//!
//!         // sender's permanent public key
//!                                   3, 3, 3, 3,  3, 3, 3, 3,
//!         3, 3, 3, 3,  3, 3, 3, 3,  3, 3, 3, 3,  3, 3, 3, 3,
//!         3, 3, 3, 3,  3, 3, 3, 3,
//!
//!         // message authentication code 
//!                                   4, 4, 4, 4,  4, 4, 4, 4,
//!         4, 4, 4, 4,  4, 4, 4, 4,
//!
//!         // sender's encrypted temporary public key
//!                                   5, 5, 5, 5,  5, 5, 5, 5,
//!         5, 5, 5, 5,  5, 5, 5, 5,  5, 5, 5, 5,  5, 5, 5, 5,
//!         5, 5, 5, 5,  5, 5, 5, 5,
//!
//!         // encrypted data
//!                                   6, 7, 8,
//!         ])
//! ```

extern crate hex;
extern crate byteorder;
use std::fmt;

use hex::ToHex;
use handshake_packet::byteorder::ByteOrder;
use keys::ToBase32;
use keys::crypto_box::PublicKey;

/// Represents the CryptoAuth session state, as defined by
/// https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#protocol
#[derive(Eq)]
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Clone)]
pub enum HandshakePacketType {
    Hello,       // 0u32
    RepeatHello, // 1u32
    Key,         // 2u32
    RepeatKey,   // 3u32
}

/// Returns a copy of the packet's sender permanent public key,
/// as a byte array.
///
/// If this is not a handshake packet, returns `Err(true)`.
/// If this is a malformed packet, returns `Err(false)`.
pub(crate) fn peek_perm_pub_key(packet: &[u8]) -> Result<[u8; 32], bool> {
    if packet.len() < 120 {
        Err(false)
    }
    else {
        let packet_type = byteorder::BigEndian::read_u32(&packet[0..4]);
        match packet_type {
            0u32 | 1u32 | 2u32 | 3u32 => {
                let mut sender_perm_pub_key = [0u8; 32];
                sender_perm_pub_key.copy_from_slice(&packet[40..72]);
                Ok(sender_perm_pub_key)
            },
            _ => Err(true),
        }
    }
}

/// Represents a raw CryptoAuth packet, as defined by
/// https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#packet-layout
pub struct HandshakePacket {
    pub raw: Vec<u8>,
}

impl fmt::Debug for HandshakePacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HandshakePacket {{
        raw:                     0x{},
        packet_type:             {:?},
        auth_challenge:          0x{} ({:?}),
        nonce:                   0x{},
        sender_perm_pub_key:     0x{} ({}),
        msg_auth_code:           0x{},
        sender_enc_temp_pub_key: 0x{},
        encrypted_data:          0x{}
        }}",
            self.raw.to_vec().to_hex(),
            self.packet_type(),
            self.auth_challenge().to_vec().to_hex(),
            self.auth_challenge(),
            self.random_nonce().to_vec().to_hex(),
            self.sender_perm_pub_key().to_vec().to_hex(), PublicKey(self.sender_perm_pub_key()).to_base32(),
            self.msg_auth_code().to_vec().to_hex(),
            self.sender_encrypted_temp_pub_key().to_vec().to_hex(),
            self.encrypted_data().to_vec().to_hex()
            )
    }
}

impl HandshakePacket {
    pub fn new_from_raw(raw: Vec<u8>) -> Result<HandshakePacket, Vec<u8>> {
        if raw.len() < 120 {
            Err(raw)
        }
        else {
            Ok(HandshakePacket { raw })
        }
    }
    /// Returns the session state of the packet if it is a known session
    /// state, as defined by
    /// https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#protocol
    ///
    /// Returns Err(value of field) if the session state field is set
    /// to an unknown value.
    pub fn packet_type(&self) -> Result<HandshakePacketType, u32> {
        match byteorder::BigEndian::read_u32(&self.raw[0..4]) {
            0u32 => Ok(HandshakePacketType::Hello),
            1u32 => Ok(HandshakePacketType::RepeatHello),
            2u32 => Ok(HandshakePacketType::Key),
            3u32 => Ok(HandshakePacketType::RepeatKey),
            n => Err(n),
        }
    }

    /// Returns a copy of the packet's Authorization Challenge.
    pub fn auth_challenge(&self) -> [u8; 12] {
        let mut auth_challenge = [0u8; 12];
        auth_challenge.copy_from_slice(&self.raw[4..16]);
        auth_challenge
    }

    /// Returns a copy of the packet's Nonce.
    pub fn random_nonce(&self) -> [u8; 24] {
        let mut random_nonce = [0u8; 24];
        random_nonce.copy_from_slice(&self.raw[16..40]);
        random_nonce
    }

    /// Returns a copy of the packet's sender permanent public key,
    /// as a byte array.
    pub fn sender_perm_pub_key(&self) -> [u8; 32] {
        let mut sender_perm_pub_key = [0u8; 32];
        sender_perm_pub_key.copy_from_slice(&self.raw[40..72]);
        sender_perm_pub_key
    }

    /// Returns a copy of the packet's Message Authentication Code.
    pub fn msg_auth_code(&self) -> [u8; 16] {
        let mut msg_auth_code = [0u8; 16];
        msg_auth_code.copy_from_slice(&self.raw[72..88]);
        msg_auth_code
    }

    /// Returns a copy of the packet's sender temporary public key,
    /// encrypted and as a byte array.
    pub fn sender_encrypted_temp_pub_key(&self) -> [u8; 32] {
        let mut sender_encrypted_temp_pub_key = [0u8; 32];
        sender_encrypted_temp_pub_key.copy_from_slice(&self.raw[88..120]);
        sender_encrypted_temp_pub_key
    }

    /// Returns a reference to the packet's encrypted “piggy-backed” data.
    pub fn encrypted_data(&self) -> &[u8] {
        // Returning a reference to a slice here because:
        // * the data can potentially be large
        // * this is likely to be the last field read, ie. the last use of
        //   the Package object so a copy would be useless.
        &self.raw[120..]
    }

    /// Returns msg_auth_code, sender_encrypted_temp_pub_key, and encrypted_data
    /// concatenated in that order.
    /// The purpose is to use it as input to the 'open' cryptographic primitive.
    pub fn sealed_data(&self) -> &[u8] {
        &self.raw[72..]
    }
}

/// Used to construct a `HandshakePacket` object field-by-field.
#[derive(Debug)]
pub struct HandshakePacketBuilder {
    pub raw: Vec<u8>,

    // Store whether these fields have been set.
    // Checked by the finalization method.
    packet_type: bool,
    auth_challenge: bool,
    random_nonce: bool,
    sender_perm_pub_key: bool,
    msg_auth_code: bool,
    sender_encrypted_temp_pub_key: bool,
    //encrypted_data: bool,
}

impl HandshakePacketBuilder {
    pub fn new() -> HandshakePacketBuilder {
        HandshakePacketBuilder {
            raw: vec![0; 120],

            packet_type: false,
            auth_challenge: false,
            random_nonce: false,
            sender_perm_pub_key: false,
            msg_auth_code: false,
            sender_encrypted_temp_pub_key: false,
            //encrypted_data: false, // Not mandatory
        }
    }

    /// Sets the session state of the packet.
    pub fn packet_type(mut self, packet_type: &HandshakePacketType) -> HandshakePacketBuilder {
        self.packet_type = true;
        let value = match *packet_type {
            HandshakePacketType::Hello => 0u32,
            HandshakePacketType::RepeatHello => 1u32,
            HandshakePacketType::Key => 2u32,
            HandshakePacketType::RepeatKey => 3u32,
        };
        byteorder::BigEndian::write_u32(&mut self.raw[0..4], value);
        self
    }

    /// Sets the packet's Authorization Challenge.
    pub fn auth_challenge(mut self, auth_challenge: &[u8; 12]) -> HandshakePacketBuilder {
        self.auth_challenge = true;
        self.raw[4..16].clone_from_slice(auth_challenge);
        self
    }

    /// Sets the packet's Nonce.
    pub fn random_nonce(mut self, random_nonce: &[u8; 24]) -> HandshakePacketBuilder {
        self.random_nonce = true;
        self.raw[16..40].clone_from_slice(random_nonce);
        self
    }

    /// Sets the packet's sender permanent public key, provided as a byte array.
    pub fn sender_perm_pub_key(mut self, sender_perm_pub_key: &[u8; 32]) -> HandshakePacketBuilder {
        self.sender_perm_pub_key = true;
        self.raw[40..72].clone_from_slice(sender_perm_pub_key);
        self
    }

    /// Sets the packet's Message Authentication Code.
    pub fn msg_auth_code(mut self, msg_auth_code: &[u8; 16]) -> HandshakePacketBuilder {
        self.msg_auth_code = true;
        self.raw[72..88].clone_from_slice(msg_auth_code);
        self
    }

    /// Sets the packet's sender temporary public key, provided encrypted and
    /// as a byte array.
    pub fn sender_encrypted_temp_pub_key(mut self, sender_encrypted_temp_pub_key: &[u8; 32]) -> HandshakePacketBuilder {
        self.sender_encrypted_temp_pub_key = true;
        self.raw[88..120].clone_from_slice(sender_encrypted_temp_pub_key);
        self
    }

    /// Sets the packet's encrypted “piggy-backed” data.
    pub fn encrypted_data(mut self, encrypted_data: &[u8]) -> HandshakePacketBuilder {
        self.raw.truncate(120);
        self.raw.extend_from_slice(encrypted_data);
        self
    }

    /// Sets the packet's msg_auth_code, sender_encrypted_temp_pub_key,
    /// and encrypted_data concatenated in that order.
    /// The purpose is to use it as output of the 'seal' cryptographic primitive.
    pub fn sealed_data(mut self, sealed_data: &[u8]) -> HandshakePacketBuilder {
        self.raw.truncate(72);
        self.raw.extend_from_slice(sealed_data);
        self
    }

    /// If all mandatory fields have been provided, returns the constructed packet.
    /// Otherwise, returns `Err([packet_type, auth_challenge, random_nonce,
    /// sender_perm_pub_key, msg_auth_code, sender_encrypted_temp_pub_key])`,
    /// Each of the items of the array being a boolean set to true if and only
    /// if the corresponding mandatory field was provided.
    pub fn finalize(self) -> Result<HandshakePacket, [bool; 6]> {
        let booleans = [self.packet_type, self.auth_challenge, self.random_nonce, self.sender_perm_pub_key, self.msg_auth_code, self.sender_encrypted_temp_pub_key];
        if booleans.contains(&false) {
            Err(booleans)
        }
        else {
            Ok(HandshakePacket { raw: self.raw, })
        }
    }
}
