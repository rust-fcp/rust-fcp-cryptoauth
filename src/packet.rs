//! Contains the `Packet` structure, and a `PacketBuilder` to
//! construct it field by field.
//!
//! # Example
//!
//! ```
//! use fcp_cryptoauth::packet::{PacketBuilder, Packet, SessionState};
//! let packet = PacketBuilder::new()
//!         .session_state(&SessionState::Key)
//!         .auth_challenge(&[1u8; 12])
//!         .random_nonce(&[2u8; 24])
//!         .sender_perm_pub_key(&[3u8; 32])
//!         .msg_auth_code(&[4u8; 16])
//!         .sender_encrypted_temp_pub_key(&[5u8; 32])
//!         .encrypted_data(vec![6u8, 7u8, 8u8])
//!         .finalize()
//!         .unwrap();
//! assert_eq!(packet.session_state(), Ok(SessionState::Key));
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

extern crate byteorder;
use packet::byteorder::ByteOrder;

/// Represents the CryptoAuth session state, as defined by
/// https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#protocol
#[derive(Eq)]
#[derive(PartialEq)]
#[derive(Debug)]
pub enum SessionState {
    Hello,       // 0u32
    RepeatHello, // 1u32
    Key,         // 2u32
    RepeatKey,   // 3u32
}

/// Represents a raw CryptoAuth packet, as defined by
/// https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#packet-layout
#[derive(Debug)]
pub struct Packet {
    pub raw: Vec<u8>,
}

impl Packet {
    /// Returns the session state of the packet if it is a known session
    /// state, as defined by
    /// https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#protocol
    ///
    /// Returns Err(value of field) if the session state field is set
    /// to an unknown value.
    pub fn session_state(&self) -> Result<SessionState, u32> {
        match byteorder::BigEndian::read_u32(&self.raw[0..4]) {
            0u32 => Ok(SessionState::Hello),
            1u32 => Ok(SessionState::RepeatHello),
            2u32 => Ok(SessionState::Key),
            3u32 => Ok(SessionState::RepeatKey),
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
}

/// Used to construct a `Packet` object field-by-field.
#[derive(Debug)]
pub struct PacketBuilder {
    pub raw: Vec<u8>,

    // Store whether these fields have been set.
    // Checked by the finalization method.
    session_state: bool,
    auth_challenge: bool,
    random_nonce: bool,
    sender_perm_pub_key: bool,
    msg_auth_code: bool,
    sender_encrypted_temp_pub_key: bool,
    //encrypted_data: bool,
}

impl PacketBuilder {
    pub fn new() -> PacketBuilder {
        PacketBuilder {
            raw: vec![0; 120],

            session_state: false,
            auth_challenge: false,
            random_nonce: false,
            sender_perm_pub_key: false,
            msg_auth_code: false,
            sender_encrypted_temp_pub_key: false,
            //encrypted_data: false, // Not mandatory
        }
    }

    /// Sets the session state of the packet.
    pub fn session_state(mut self, session_state: &SessionState) -> PacketBuilder {
        self.session_state = true;
        let value = match *session_state {
            SessionState::Hello => 0u32,
            SessionState::RepeatHello => 1u32,
            SessionState::Key => 2u32,
            SessionState::RepeatKey => 3u32,
        };
        byteorder::BigEndian::write_u32(&mut self.raw[0..4], value);
        self
    }

    /// Sets the packet's Authorization Challenge.
    pub fn auth_challenge(mut self, auth_challenge: &[u8; 12]) -> PacketBuilder {
        self.auth_challenge = true;
        self.raw[4..16].clone_from_slice(auth_challenge);
        self
    }

    /// Sets the packet's Nonce.
    pub fn random_nonce(mut self, random_nonce: &[u8; 24]) -> PacketBuilder {
        self.random_nonce = true;
        self.raw[16..40].clone_from_slice(random_nonce);
        self
    }

    /// Sets the packet's sender permanent public key, provided as a byte array.
    pub fn sender_perm_pub_key(mut self, sender_perm_pub_key: &[u8; 32]) -> PacketBuilder {
        self.sender_perm_pub_key = true;
        self.raw[40..72].clone_from_slice(sender_perm_pub_key);
        self
    }

    /// Sets the packet's Message Authentication Code.
    pub fn msg_auth_code(mut self, msg_auth_code: &[u8; 16]) -> PacketBuilder {
        self.msg_auth_code = true;
        self.raw[72..88].clone_from_slice(msg_auth_code);
        self
    }

    /// Sets the packet's sender temporary public key, provided encrypted and
    /// as a byte array.
    pub fn sender_encrypted_temp_pub_key(mut self, sender_encrypted_temp_pub_key: &[u8; 32]) -> PacketBuilder {
        self.sender_encrypted_temp_pub_key = true;
        self.raw[88..120].clone_from_slice(sender_encrypted_temp_pub_key);
        self
    }

    /// Sets the packet's encrypted “piggy-backed” data.
    pub fn encrypted_data(mut self, mut encrypted_data: Vec<u8>) -> PacketBuilder {
        self.raw.truncate(120);
        self.raw.append(&mut encrypted_data);
        self
    }

    /// If all mandatory fields have been provided, returns the constructed packet.
    /// Otherwise, returns `Err([session_state, auth_challenge, random_nonce,
    /// sender_perm_pub_key, msg_auth_code, sender_encrypted_temp_pub_key])`,
    /// Each of the items of the array being a boolean set to true if and only
    /// if the corresponding mandatory field was provided.
    pub fn finalize(self) -> Result<Packet, [bool; 6]> {
        let booleans = [self.session_state, self.auth_challenge, self.random_nonce, self.sender_perm_pub_key, self.msg_auth_code, self.sender_encrypted_temp_pub_key];
        if booleans.contains(&false) {
            Err(booleans)
        }
        else {
            Ok(Packet { raw: self.raw, })
        }
    }
}
