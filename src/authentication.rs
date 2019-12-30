//! Contains code related to the authorization challenge, as defined by
//! https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#authorization-challenges
//! and
//! https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#authentication-field
//!
//! # Examples
//!
//! None credentials:
//!
//! ```
//! use fcp_cryptoauth::authentication::*;
//! # use fcp_cryptoauth::session::{Session, SessionState};
//! # use fcp_cryptoauth::cryptography::crypto_box::gen_keypair;
//! # let (my_pk, my_sk) = gen_keypair();
//! # let (their_pk, _) = gen_keypair();
//! # let session = Session::new(my_pk, my_sk, their_pk, SessionState::UninitializedKnownPeer);

//! let credentials = Credentials::None;
//! let bytes = credentials.to_auth_challenge_bytes(&session);
//! assert_eq!(bytes[0], 0u8);
//! // Other bytes are random, as specified.
//! ```
//!
//! Password credentials:
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
//! let credentials = Credentials::Password { password: password };
//! let bytes = credentials.to_auth_challenge_bytes(&session);
//! assert_eq!(bytes[0], 1u8);
//! assert_eq!(bytes[1..8], [0xad, 0xe8, 0x8f, 0xc7, 0xa2, 0x14, 0x98]); // sha256(sha256("foo"))[1..8]
//! assert_eq!(bytes[8..12], [0, 0, 0, 0]);
//! ```
//!
//! Login+Password credentials:
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
//! let credentials = Credentials::LoginPassword { login: login, password: password };
//! let bytes = credentials.to_auth_challenge_bytes(&session);
//! assert_eq!(bytes[0], 2u8);
//! assert_eq!(bytes[1..8], [0x26, 0xb4, 0x6b, 0x68, 0xff, 0xc6, 0x8f]); // sha256("bar")[1..8]
//! assert_eq!(bytes[8..12], [0, 0, 0, 0]);
//! ```

extern crate rust_sodium;
use rust_sodium::randombytes::randombytes;

use cryptography::crypto_box::PrecomputedKey;
use cryptography::sha256;
use cryptography::{shared_secret_from_keys, shared_secret_from_password};
use session::Session;

/// Used for specifying authorization credentials of a peer,
/// either oneself or an incoming peer.
///
/// Represents an authorization method and its data, as defined by
/// https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#authorization-challenges
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum Credentials {
    /// This is the preferred credentials method, with a login and
    /// a password.
    ///
    /// The login is used to tell the other party who we are,
    /// and the password is combined with cryptographic keys of the
    /// two peers to computed a shared secret, in order to provide
    /// a stronger authentication than just checking public keys.
    ///
    /// The password is not revealed to someone who does not know it,
    /// even if they have the secret keys of both peers.
    LoginPassword {
        /// The login used to tell who we are. Does not have to be
        /// a secret, but must be unique.
        ///
        /// Seven bytes of its sha256 hash are sent unencrypted
        /// before authentication.
        login: Vec<u8>,
        /// The password which will be combined with keys of other
        /// peers to prove who we are.
        password: Vec<u8>,
    },

    /// Password-only credentials. This method is not recommended
    /// and may be dropped in the future. See
    /// https://github.com/cjdelisle/cjdns/blob/cjdns-v18/util/version/Version.h#L357-L363
    /// for details about why the LoginPassword method is prefered.
    Password {
        /// The password used to tell who we are and prove it.
        /// It must be unique.
        ///
        /// Seven bytes of its double-sha256 hash are sent unencrypted
        /// before authentication.
        password: Vec<u8>,
    },

    /// Pseudo-credentials used for when authorization is not needed.
    /// Do not use it for outgoing connections.
    None,
}

pub trait ToAuthChallenge {
    fn to_auth_challenge_bytes(&self, session: &Session) -> [u8; 12];
    fn make_shared_secret(&self, session: &Session) -> PrecomputedKey;
    fn make_shared_secret_key(&self, session: &Session) -> PrecomputedKey {
        self.make_shared_secret(session)
    }
}

impl ToAuthChallenge for Credentials {
    /// Generates a byte array representation of the auth challenge, as defined by:
    /// https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#authentication-field
    fn to_auth_challenge_bytes(&self, _session: &Session) -> [u8; 12] {
        match *self {
            Credentials::None => {
                // “If the AuthType is set to zero, all AuthType Specific fields are disregarded and SHOULD be set to random numbers.”
                // https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#authtype-zero
                let bytes = randombytes(11);
                [
                    0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                    bytes[7], bytes[8], bytes[9], bytes[10],
                ]
            }
            Credentials::Password { ref password } => {
                // https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#authtype-one
                // The whitepaper says there is combination with curve25519 keys,
                // but the code <https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/crypto/CryptoAuth.c#L114-L133>
                // seems to just hash the password twice.
                let hashed_password = sha256::hash(&password).0;
                let hash = sha256::hash(&hashed_password).0;
                [
                    1, hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], 0, 0, 0, 0,
                ]
            }
            Credentials::LoginPassword {
                password: _,
                ref login,
            } => {
                let hash = sha256::hash(&login).0;
                [
                    2, hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], 0, 0, 0, 0,
                ]
            }
        }
    }

    fn make_shared_secret(&self, session: &Session) -> PrecomputedKey {
        match *self {
            Credentials::None => {
                shared_secret_from_keys(&session.my_perm_sk, &session.their_perm_pk)
            }
            Credentials::Password { ref password }
            | Credentials::LoginPassword {
                ref password,
                login: _,
            } => shared_secret_from_password(password, &session.my_perm_sk, &session.their_perm_pk),
        }
    }
}
