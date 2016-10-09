use std::collections::HashMap;

use keys::{SecretKey, PublicKey};
use cryptography::{hash_password, PASSWORD_DIGEST_BYTES};


pub struct PasswordStore<Peer> {
    my_perm_sk: SecretKey,
    hashed_password_peers: HashMap<[u8; PASSWORD_DIGEST_BYTES], Peer>,
}

impl<Peer> PasswordStore<Peer> {
    pub fn new(my_perm_sk: SecretKey) -> PasswordStore<Peer> {
        PasswordStore { my_perm_sk: my_perm_sk, hashed_password_peers: HashMap::new() }
    }

    pub fn add_peer(&mut self, password: &Vec<u8>, their_perm_pk: &PublicKey, peer: Peer) {
        let hashed_password = hash_password(password, &self.my_perm_sk, their_perm_pk);
        self.hashed_password_peers.insert(hashed_password, peer);
    }

    pub fn get_peer(&self, hashed_password: &[u8; PASSWORD_DIGEST_BYTES]) -> Option<&Peer> {
        self.hashed_password_peers.get(hashed_password)
    }
}
