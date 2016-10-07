extern crate rust_sodium;
use rust_sodium::crypto::box_::curve25519xsalsa20poly1305 as crypto_box;

pub struct PublicKey {
    pub crypto_box_key: crypto_box::PublicKey,
}
impl PublicKey {
    pub fn new(bytes: &[u8; crypto_box::PUBLICKEYBYTES]) -> PublicKey {
        PublicKey { crypto_box_key: crypto_box::PublicKey::from_slice(bytes).unwrap(), }
    }

    pub fn bytes(&self) -> &[u8; crypto_box::PUBLICKEYBYTES] {
        &self.crypto_box_key.0
    }
}

pub struct SecretKey {
    pub crypto_box_key: crypto_box::SecretKey,
}
impl SecretKey {
    pub fn new(bytes: &[u8; crypto_box::SECRETKEYBYTES]) -> SecretKey {
        SecretKey { crypto_box_key: crypto_box::SecretKey::from_slice(bytes).unwrap(), }
    }

    pub fn bytes(&self) -> &[u8; crypto_box::SECRETKEYBYTES] {
        &self.crypto_box_key.0
    }
}

pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let (cb_pk, cb_sk) = crypto_box::gen_keypair();
    (PublicKey { crypto_box_key: cb_pk }, SecretKey { crypto_box_key: cb_sk })
}
