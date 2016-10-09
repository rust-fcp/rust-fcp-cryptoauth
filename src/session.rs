//! Contains the `Session` structure, which stores the state of a
//! CryptoAuth session.

extern crate rust_sodium;

use std::fmt;

use rust_sodium::crypto::box_::curve25519xsalsa20poly1305 as crypto_box;

use keys::{SecretKey, PublicKey};

pub enum SessionState {
    Uninitialized,
    ReceivedHello,
    SentHello, // Implies not(ReceivedHello)
    SentKey, // Implies ReceivedHello
    Established(u32), // Implies SentKey or SentHello. The argument is a nonce > 4.
}

/// Stores the state of a CryptoAuth session (nonce, permanent keys,
/// temporary keys).
pub struct Session {
    pub state: SessionState,

    pub my_perm_pk: PublicKey,
    pub my_perm_sk: SecretKey,
    pub their_perm_pk: PublicKey,

    pub my_temp_pk: crypto_box::PublicKey,
    pub my_temp_sk: crypto_box::SecretKey,

    pub shared_secret: Option<[u8; 32]>,
    pub their_temp_pk: Option<crypto_box::PublicKey>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Session {{ ... }}")
    }
}

impl Session {
    /// Creates a new session using permanent keys.
    /// 'initiator' determines whether we are the one to send the Hello packet
    /// (and receive the Key packet)
    pub fn new(initiator: bool, my_pk: PublicKey, my_sk: SecretKey, their_pk: PublicKey) -> Session {
        // Temporary keys used only for this session.
        let (my_temp_pk, my_temp_sk) = crypto_box::gen_keypair();

        Session {
            state: if initiator { SessionState::Uninitialized } else { SessionState::ReceivedHello },

            my_perm_pk: my_pk,
            my_perm_sk: my_sk,
            their_perm_pk: their_pk,

            my_temp_pk: my_temp_pk,
            my_temp_sk: my_temp_sk,

            shared_secret: None,
            their_temp_pk: None,
        }
    }
}
