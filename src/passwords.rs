use std::collections::HashMap;

use cryptography::sha256;

pub struct PasswordStore<Peer: Clone> {
    // sha256(sha256(password))[1..7] -> (password, peer)
    password_peers: HashMap<[u8; 7], Vec<(Vec<u8>, Peer)>>,
    // sha256(login)[1..7] -> (password, peer)
    login_peers: HashMap<[u8; 7], Vec<(Vec<u8>, Peer)>>,
}

impl<Peer: Clone> PasswordStore<Peer> {
    pub fn new() -> PasswordStore<Peer> {
        PasswordStore { password_peers: HashMap::new(), login_peers: HashMap::new() }
    }

    fn add_password_peer(&mut self, password: Vec<u8>, peer: Peer) {
        let doublehashed_password = sha256::hash(&sha256::hash(&password).0);
        let mut bucket = {
            let hashed_password_slice = &doublehashed_password[1..8];
            if let None = self.password_peers.get_mut(hashed_password_slice) {
                let bucket = Vec::new();
                let mut key = [0u8; 7];
                key.copy_from_slice(hashed_password_slice);
                self.password_peers.insert(key, bucket);
            }
            self.password_peers.get_mut(hashed_password_slice).unwrap()
        };
        bucket.push((password, peer));
    }

    fn add_login_peer(&mut self, login: &Vec<u8>, password: Vec<u8>, peer: Peer) {
        let hashed_login = sha256::hash(login);
        let mut bucket = {
            let hashed_login_slice = &hashed_login[1..8];
            if let None = self.login_peers.get_mut(hashed_login_slice) {
                let bucket = Vec::new();
                let mut key = [0u8; 7];
                key.copy_from_slice(hashed_login_slice);
                self.login_peers.insert(key, bucket);
            }
            self.login_peers.get_mut(hashed_login_slice).unwrap()
        };
        bucket.push((password, peer));
    }

    pub fn add_peer(&mut self, login: Option<&Vec<u8>>, password: Vec<u8>, peer: Peer) {
        self.add_password_peer(password.clone(), peer.clone());
        match login {
            Some(login) => self.add_login_peer(login, password, peer),
            None => (),
        };
    }

    /// Returns all peers whose sha256(sha256(password))[1..7] match
    pub fn get_candidate_peers_from_password_doublehash_slice(&self, doublehashed_password_slice: &[u8; 7]) -> Option<&Vec<(Vec<u8>, Peer)>> {
        self.password_peers.get(doublehashed_password_slice)
    }

    /// Returns all peers whose sha256(login)[1..7] match
    pub fn get_candidate_peers_from_login_hash_slice(&self, hashed_login_slice: &[u8; 7]) -> Option<&Vec<(Vec<u8>, Peer)>> {
        self.login_peers.get(hashed_login_slice)
    }
}
