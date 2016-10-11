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
//! # use fcp_cryptoauth::session::{Session, SessionState};
//! # use fcp_cryptoauth::cryptography::crypto_box::gen_keypair;
//! # let (my_pk, my_sk) = gen_keypair();
//! # let (their_pk, _) = gen_keypair();
//! # let session = Session::new(my_pk, my_sk, their_pk, SessionState::UninitializedKnownPeer);

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
//! # use fcp_cryptoauth::session::{Session, SessionState};
//! # use fcp_cryptoauth::cryptography::crypto_box::gen_keypair;
//! # let (my_pk, my_sk) = gen_keypair();
//! # let (their_pk, _) = gen_keypair();
//! # let session = Session::new(my_pk, my_sk, their_pk, SessionState::UninitializedKnownPeer);
//!
//! let password = "foo".to_owned().into_bytes();
//! let challenge = AuthChallenge::Password { password: password };
//! let bytes = challenge.to_bytes(&session);
//! assert_eq!(bytes[0], 1u8);
//! assert_eq!(bytes[1..8], [0xad, 0xe8, 0x8f, 0xc7, 0xa2, 0x14, 0x98]); // sha256(sha256("foo"))[1..8]
//! assert_eq!(bytes[8..12], [0, 0, 0, 0]);
//! ```
//!
//! Login+Password challenge:
//!
//! ```
//! use fcp_cryptoauth::authentication::*;
//! # use fcp_cryptoauth::session::{Session, SessionState};
//! # use fcp_cryptoauth::cryptography::crypto_box::gen_keypair;
//! # let (my_pk, my_sk) = gen_keypair();
//! # let (their_pk, _) = gen_keypair();
//! # let session = Session::new(my_pk, my_sk, their_pk, SessionState::UninitializedKnownPeer);
//!
//! let login = "foo".to_owned().into_bytes();
//! let password = "bar".to_owned().into_bytes();
//! let challenge = AuthChallenge::LoginPassword { login: login, password: password };
//! let bytes = challenge.to_bytes(&session);
//! assert_eq!(bytes[0], 2u8);
//! assert_eq!(bytes[1..8], [0x26, 0xb4, 0x6b, 0x68, 0xff, 0xc6, 0x8f]); // sha256("bar")[1..8]
//! assert_eq!(bytes[8..12], [0, 0, 0, 0]);
//! ```

extern crate rust_sodium;
use rust_sodium::randombytes::randombytes;

use session::Session;
use cryptography::crypto_box::PrecomputedKey;
use cryptography::sha256;
use cryptography::{shared_secret_from_password, PASSWORD_DIGEST_BYTES};

/// Represents an authorization method and its data, as defined by
/// https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#authorization-challenges
#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq)]
#[derive(PartialEq)]
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
            AuthChallenge::LoginPassword { password: _, ref login } => {
                let hash = sha256::hash(&login).0;
                [
                    2,       hash[1], hash[2], hash[3],
                    hash[4], hash[5], hash[6], hash[7],
                    0,       0,       0,       0,
                ]
            },
        }
    }

    pub fn make_shared_secret(&self, session: &Session) -> [u8; PASSWORD_DIGEST_BYTES] {
        match *self {
            AuthChallenge::None => unimplemented!(), // TODO
            AuthChallenge::Password { ref password } |
            AuthChallenge::LoginPassword { ref password, login: _ } => {
                shared_secret_from_password(password, &session.my_perm_sk, &session.their_perm_pk)
            }
        }
    }

    pub fn make_shared_secret_key(&self, session: &Session) -> PrecomputedKey {
        PrecomputedKey::from_slice(&self.make_shared_secret(session)).unwrap()
    }
}

#[derive(Debug)]
#[derive(Clone)]
pub enum AuthFailure {
    UnknownAuthMethod(u8), // An incoming peer tried an auth method that is not None/Password/LoginPassword
    AuthNone, // An incoming peer tried to connect with None auth.
    InvalidCredentials, // An incoming peer tried to connect with credentials unknown to us.
    WrongPublicKey, // A peer used a public key different than expected.
}
