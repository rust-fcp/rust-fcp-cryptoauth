//! Contains the `Session` structure, which stores the state of a
//! CryptoAuth session.

use std::fmt;

use cryptography::crypto_box;
use cryptography::crypto_box::{PublicKey, SecretKey, PrecomputedKey, Nonce};

#[derive(Debug)]
#[derive(Clone)]
#[derive(Eq)]
#[derive(PartialEq)]
pub enum SessionState {
    UninitializedUnknownPeer,
    UninitializedKnownPeer,
    SentHello { handshake_nonce: Nonce, shared_secret_key: PrecomputedKey },
    ReceivedHello { their_temp_pk: PublicKey, handshake_nonce: Nonce, shared_secret_key: PrecomputedKey },
    WaitingKey { their_temp_pk: PublicKey, handshake_nonce: Nonce, shared_secret_key: PrecomputedKey }, // When we received a Hello from a lower key, don't send an Hello because it would reset their session
    SentKey { their_temp_pk: PublicKey, handshake_nonce: Nonce, shared_secret_key: PrecomputedKey },
    Established {
        their_temp_pk: PublicKey,
        /// Used to open RepeatKey packets
        handshake_shared_secret_key: PrecomputedKey,
        shared_secret_key: PrecomputedKey,
        initiator_is_me: bool
    },
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

    pub my_last_nonce: u32,
    pub their_nonce_offset: u32, // their last nonce
    pub their_nonce_bitfield: u64,
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
    pub fn new(my_pk: PublicKey, my_sk: SecretKey, their_pk: PublicKey, initial_state: SessionState) -> Session {
        // Temporary keys used only for this session.
        let (my_temp_pk, my_temp_sk) = crypto_box::gen_keypair();

        Session {
            state: initial_state,

            my_perm_pk: my_pk,
            my_perm_sk: my_sk,
            their_perm_pk: their_pk,

            my_temp_pk: my_temp_pk,
            my_temp_sk: my_temp_sk,

            my_last_nonce: 3u32,
            their_nonce_offset: 4u32,
            their_nonce_bitfield: 0u64,
        }
    }

    /// Resets the temporary keys.
    pub fn reset(&mut self) {
        let (my_temp_pk, my_temp_sk) = crypto_box::gen_keypair();
        self.my_temp_pk = my_temp_pk;
        self.my_temp_sk = my_temp_sk;
    }
}
