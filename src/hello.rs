//! Creates and reads CryptoAuth Hello packets

extern crate rust_sodium;
use rust_sodium::crypto::box_::curve25519xsalsa20poly1305 as crypto_box;
use rust_sodium::crypto::scalarmult::curve25519 as scalarmult;
use rust_sodium::crypto::hash::sha256;

use authentication;
use session;
use packet::{Packet, PacketBuilder, SessionState};

/// Implements Hello packet creation, as defined by
/// https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#hello-repeathello
pub fn create_hello(session_: &mut session::Session, auth_challenge: authentication::AuthChallenge) -> Packet {
    // Paragraph 1
    let random_nonce = &session_.nonce.0;

    // Paragraph 2
    let sender_perm_pub_key = session_.my_perm_pk.bytes();

    // Paragraph 3
    assert_eq!(scalarmult::SCALARBYTES, crypto_box::PUBLICKEYBYTES);
    assert_eq!(scalarmult::GROUPELEMENTBYTES, crypto_box::SECRETKEYBYTES);
    let product = scalarmult::scalarmult(
            &scalarmult::Scalar::from_slice(session_.my_perm_sk.bytes()).unwrap(),
            &scalarmult::GroupElement::from_slice(session_.their_perm_pk.bytes()).unwrap(),
            );
    let mut shared_secret_preimage = product.0.to_vec();
    match auth_challenge {
        authentication::AuthChallenge::None => unimplemented!(), // TODO
        authentication::AuthChallenge::Password { ref password } |
        authentication::AuthChallenge::LoginPassword { ref password, login: _ } => {
            shared_secret_preimage.extend(&sha256::hash(&*password).0)
        }
    };
    let shared_secret = sha256::hash(&shared_secret_preimage).0;
    assert_eq!(session_.shared_secret, None);
    session_.shared_secret = Some(shared_secret);

    // Paragraph 4: temporary keys are generated in Session::new()

    // Paragraph 5
    let mut  my_encrypted_temp_pk = [0u8; 32];
    my_encrypted_temp_pk.clone_from_slice(
            &crypto_box::seal(&shared_secret, &session_.nonce, &session_.my_temp_pk, &session_.my_temp_sk));

    // Construction of the packet
    let packet = PacketBuilder::new()
            .session_state(&SessionState::Hello)
            .auth_challenge(&auth_challenge.to_bytes(session_))
            .random_nonce(random_nonce)
            .sender_perm_pub_key(sender_perm_pub_key)
            .msg_auth_code(&[0u8; 16]) // TODO: msg auth
            .sender_encrypted_temp_pub_key(&my_encrypted_temp_pk)
            .finalize().unwrap();
    packet
}
