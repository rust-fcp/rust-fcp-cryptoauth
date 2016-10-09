use rust_sodium::crypto::box_::curve25519xsalsa20poly1305 as crypto_box;
use rust_sodium::crypto::scalarmult::curve25519 as scalarmult;
use rust_sodium::crypto::hash::sha256;

use keys::{SecretKey, PublicKey};

/// Number of bytes in a password digest.
pub const PASSWORD_DIGEST_BYTES: usize = sha256::DIGESTBYTES;

/// Implements the fancy password hashing used by the FCP, decribed in paragraph 4
/// of https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#hello-repeathello
pub fn hash_password(password: &Vec<u8>, my_perm_sk: &SecretKey, their_perm_pk: &PublicKey) -> [u8; PASSWORD_DIGEST_BYTES] {
    assert_eq!(scalarmult::SCALARBYTES, crypto_box::PUBLICKEYBYTES);
    assert_eq!(scalarmult::GROUPELEMENTBYTES, crypto_box::SECRETKEYBYTES);
    let product = scalarmult::scalarmult(
            &scalarmult::Scalar::from_slice(&my_perm_sk.crypto_box_key.0).unwrap(),
            &scalarmult::GroupElement::from_slice(&their_perm_pk.crypto_box_key.0).unwrap(),
            );
    let mut shared_secret_preimage = product.0.to_vec();
    shared_secret_preimage.extend(&sha256::hash(&*password).0);
    sha256::hash(&shared_secret_preimage).0
}

