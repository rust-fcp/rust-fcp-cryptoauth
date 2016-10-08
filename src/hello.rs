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
///
/// # Examples
///
/// ```
/// use fcp_cryptoauth::authentication::AuthChallenge;
/// use fcp_cryptoauth::session::Session;
/// use fcp_cryptoauth::keys::{gen_keypair, PublicKey};
/// use fcp_cryptoauth::hello::create_hello;
///
/// let (my_pk, my_sk) = gen_keypair();
/// let their_pk = PublicKey::new_from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
/// // Corresponding secret key: 824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8
/// let mut session = Session::new(my_pk, my_sk, their_pk);
///
/// let login = "foo".to_owned().into_bytes();
/// let password = "bar".to_owned().into_bytes();
/// let challenge = AuthChallenge::LoginPassword { login: login, password: password };
///
/// let hello = create_hello(&mut session, challenge);
/// let bytes = hello.raw;
/// println!("{:?}", bytes);
/// ```
pub fn create_hello(session_: &mut session::Session, auth_challenge: authentication::AuthChallenge) -> Packet {
    /////////////////////////////////////
    // Paragraph 1
    let random_nonce = &session_.nonce.0;

    /////////////////////////////////////
    // Paragraph 2
    let sender_perm_pub_key = session_.my_perm_pk.bytes();

    /////////////////////////////////////
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

    /////////////////////////////////////
    // Paragraph 4
    // temporary keys were already generated in Session::new()

    /////////////////////////////////////
    // Paragraph 5
    // Note: the implementations details given in paragraph 6 only apply to
    // the C API, not to the Rust API.

    // The seal function will return a buffer containing
    // 16 bytes of MAC (msg auth code), followed by 32 bytes of encrypted data
    let authenticated_sealed_temp_pk = crypto_box::seal(&shared_secret, &session_.nonce, &session_.my_temp_pk, &session_.my_temp_sk);
    assert_eq!(authenticated_sealed_temp_pk.len(), 16+32);

    // And we can extract these
    let mut msg_auth_code = [0u8; 16];
    msg_auth_code.copy_from_slice(&authenticated_sealed_temp_pk[0..16]);
    let mut my_encrypted_temp_pk = [0u8; 32];
    my_encrypted_temp_pk.copy_from_slice(&authenticated_sealed_temp_pk[16..48]);

    // Remark: actually, we could do this faster. Here, we split the
    // sealed value into msg_auth_code and sender_encrypted_temp_pub_key,
    // but these too value are then concatenated in the same order in
    // the packet's serialization.
    // But I prefer to keep the code readable.

    /////////////////////////////////////
    // Construction of the packet
    let packet = PacketBuilder::new()
            .session_state(&SessionState::Hello)
            .auth_challenge(&auth_challenge.to_bytes(session_))
            .random_nonce(random_nonce)
            .sender_perm_pub_key(sender_perm_pub_key)
            .msg_auth_code(&msg_auth_code)
            .sender_encrypted_temp_pub_key(&my_encrypted_temp_pk)
            .finalize().unwrap();
    packet
}
