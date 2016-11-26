pub use rust_sodium::crypto::box_::curve25519xsalsa20poly1305 as crypto_box;
pub use rust_sodium::crypto::scalarmult::curve25519 as scalarmult;
pub use rust_sodium::crypto::hash::sha256;

use auth_failure::AuthFailure;

/// Number of bytes in a password digest.
pub const PASSWORD_DIGEST_BYTES: usize = sha256::DIGESTBYTES;

/// Implements the fancy password hashing used by the FCP, decribed in paragraph 4
/// of https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#hello-repeathello
pub fn shared_secret_from_password(password: &[u8], my_perm_sk: &crypto_box::SecretKey, their_perm_pk: &crypto_box::PublicKey) -> crypto_box::PrecomputedKey {
    assert_eq!(scalarmult::SCALARBYTES, crypto_box::PUBLICKEYBYTES);
    assert_eq!(scalarmult::GROUPELEMENTBYTES, crypto_box::SECRETKEYBYTES);
    let product = scalarmult::scalarmult(
            &scalarmult::Scalar::from_slice(&my_perm_sk.0).unwrap(),
            &scalarmult::GroupElement::from_slice(&their_perm_pk.0).unwrap(),
            );
    let mut shared_secret_preimage = product.0.to_vec();
    shared_secret_preimage.extend(&sha256::hash(password).0);
    let shared_secret = sha256::hash(&shared_secret_preimage).0;
    crypto_box::PrecomputedKey::from_slice(&shared_secret).unwrap()
}

/// AuthNone Hello packets: my_sk and their_pk are permanent keys
/// Key packets: my_sk is permanent, their_pk is temporary
/// data packets: my_sk and their_pk are temporary keys
pub fn shared_secret_from_keys(my_sk: &crypto_box::SecretKey, their_pk: &crypto_box::PublicKey) -> crypto_box::PrecomputedKey {
    crypto_box::precompute(their_pk, my_sk)
}

/// unseals the concatenation of fields msg_auth_code, sender_encrypted_temp_pk, and
/// encrypted_data of a packet.
/// If authentication was successful, returns the sender's temp_pk and the
/// data, unencrypted.
pub fn open_packet_end(packet_end: &[u8], shared_secret: &crypto_box::PrecomputedKey, nonce: &crypto_box::Nonce) -> Result<(crypto_box::PublicKey, Vec<u8>), AuthFailure> {
    if packet_end.len() < crypto_box::MACBYTES {
        return Err(AuthFailure::PacketTooShort(format!("Packet end: {}", packet_end.len())))
    }
    match crypto_box::open_precomputed(packet_end, nonce, &shared_secret) {
        Err(_) => Err(AuthFailure::CorruptedPacket),
        Ok(buf) => {
            let mut pk = [0u8; crypto_box::PUBLICKEYBYTES];
            pk.copy_from_slice(&buf[0..crypto_box::PUBLICKEYBYTES]);
            let their_temp_pk = crypto_box::PublicKey::from_slice(&pk).unwrap();
            let data = buf[crypto_box::PUBLICKEYBYTES..].to_vec();
            Ok((their_temp_pk, data))
        },
    }
}

