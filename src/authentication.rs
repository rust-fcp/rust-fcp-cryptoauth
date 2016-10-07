//! Contains code related to the authorization challenge, as defined by
//! https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#authorization-challenges
//! and
//! https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#authentication-field
//! 
//! # Examples
//!
//! None challenge:
//!
//! ```
//! use fcp_cryptoauth::authentication::*;
//! # use fcp_cryptoauth::session::Session;
//! # use fcp_cryptoauth::keys::gen_keypair;
//! # let (my_pk, my_sk) = gen_keypair();
//! # let (their_pk, _) = gen_keypair();
//! # let session = Session::new(my_pk, my_sk, their_pk);

//! let challenge = AuthChallenge::None;
//! let bytes = challenge.to_bytes(&session);
//! assert_eq!(bytes[0], 0u8);
//! // Other bytes are random, as specified.
//! ```
//!
//! Password challenge:
//!
//! ```
//! use fcp_cryptoauth::authentication::*;
//! # use fcp_cryptoauth::session::Session;
//! # use fcp_cryptoauth::keys::gen_keypair;
//! # let (my_pk, my_sk) = gen_keypair();
//! # let (their_pk, _) = gen_keypair();
//! # let session = Session::new(my_pk, my_sk, their_pk);
//!
//! let mut password = "foobar".to_owned().into_bytes();
//! let challenge = AuthChallenge::Password { password: password };
//! let bytes = challenge.to_bytes(&session);
//! assert_eq!(bytes[0], 1u8);
//! assert!(bytes[1..8] != [0, 0, 0, 0, 0, 0, 0]); // Hashed data
//! assert_eq!(bytes[8..12], [0, 0, 0, 0]);
//! ```

extern crate rust_sodium;
use rust_sodium::randombytes::randombytes;
use rust_sodium::crypto::hash::sha256;

use session::Session;

/// Represents an authorization method and its data, as defined by
/// https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#authorization-challenges
pub enum AuthChallenge {
    None,
    Password { password: Vec<u8> },
    LoginPassword { password: Vec<u8>, login: Vec<u8> },
}

impl AuthChallenge {
    /// Generates a byte array representation of the auth challenge, as defined by:
    /// https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#authentication-field
    pub fn to_bytes(&self, session: &Session) -> [u8; 12] {
        match *self {
            AuthChallenge::None => {
                // “If the AuthType is set to zero, all AuthType Specific fields are disregarded and SHOULD be set to random numbers.”
                // https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#authtype-zero
                let bytes = randombytes(11);
                [
                    0,        bytes[0], bytes[1], bytes[2],
                    bytes[3], bytes[4], bytes[5], bytes[6],
                    bytes[7], bytes[8], bytes[9], bytes[10],
                ]
            }
            AuthChallenge::Password { ref password } => {
                // https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#authtype-one
                // The whitepaper says there is combination with curve25519 keys,
                // but the code <https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/crypto/CryptoAuth.c#L114-L133>
                // seems to just hash the password twice.
                let hashed_password = sha256::hash(&password).0;
                let hash = sha256::hash(&hashed_password).0;
                [
                    1,       hash[1], hash[2], hash[3],
                    hash[4], hash[5], hash[6], hash[7],
                    0,       0,       0,       0,
                ]
            },
            AuthChallenge::LoginPassword { password: _, login: _ } => {
                unimplemented!() // TODO
            },
        }
    }
}