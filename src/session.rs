//! Contains the `Session` structure, which stores the state of a
//! CryptoAuth session.

extern crate rust_sodium;
use rust_sodium::crypto::box_::curve25519xsalsa20poly1305 as crypto_box;

use keys::{SecretKey, PublicKey};

/// Stores the state of a CryptoAuth session (nonce, permanent keys,
/// temporary keys).
pub struct Session {
    pub nonce: crypto_box::Nonce,

    pub my_perm_pk: PublicKey,
    pub my_perm_sk: SecretKey,
    pub their_perm_pk: PublicKey,

    pub my_temp_pk: crypto_box::PublicKey,
    pub my_temp_sk: crypto_box::SecretKey,
}

impl Session {
    /// Creates a new session using permanent keys.
    pub fn new(my_pk: PublicKey, my_sk: SecretKey, their_pk: PublicKey) -> Session {
        // Temporary keys used only for this session.
        let (my_temp_pk, my_temp_sk) = crypto_box::gen_keypair();

        Session {
            nonce: crypto_box::gen_nonce(),

            my_perm_pk: my_pk,
            my_perm_sk: my_sk,
            their_perm_pk: their_pk,

            my_temp_pk: my_temp_pk,
            my_temp_sk: my_temp_sk,
        }
    }
}
