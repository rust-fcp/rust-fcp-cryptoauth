//! Creates and reads CryptoAuth Hello packets

extern crate rust_sodium;
use rust_sodium::crypto::box_::curve25519xsalsa20poly1305 as crypto_box;

use cryptography::hash_password;
use keys;
use authentication;
use session;
use packet::{Packet, PacketBuilder, SessionState};
use passwords::PasswordStore;

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
    let shared_secret = match auth_challenge {
        authentication::AuthChallenge::None => unimplemented!(), // TODO
        authentication::AuthChallenge::Password { ref password } |
        authentication::AuthChallenge::LoginPassword { ref password, login: _ } => {
            hash_password(password, &session_.my_perm_sk, &session_.their_perm_pk)
        }
    };
    assert_eq!(session_.shared_secret, None);
    session_.shared_secret = Some(shared_secret);

    /////////////////////////////////////
    // Paragraph 4
    // temporary keys were already generated in Session::new()

    /////////////////////////////////////
    // Paragraph 5
    // This part is a bit tricky. Hold on tight.

    // Here, we will encrypt the temp pub *key* using the *shared secret*.
    // This may seem counter-intuitive; but it is actually valid because
    // encryption keys and symmetric secrets all are 32-bits long.
    let authenticated_sealed_temp_pk = crypto_box::seal_precomputed(
            &session_.my_temp_pk.0, // We encrypt the temp pub key
            &session_.nonce, // with the Nonce
            &crypto_box::PrecomputedKey::from_slice(&shared_secret).unwrap(), // using the shared secret.
            );
    assert_eq!(authenticated_sealed_temp_pk.len(), 16+32);

    // The seal_precomputed function will return a buffer containing
    // 16 bytes of MAC (msg auth code), followed by 32 bytes of encrypted data
    // (The implementations details given in paragraph 6 only apply to
    // the C API, not to the Rust API.)

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

/// Read a network packet, assumed to be an Hello or a RepeatHello.
///
/// TODO: improve error return
pub fn read_hello<'a, Peer>(my_perm_pk: keys::PublicKey, my_perm_sk: keys::SecretKey, password_store: &'a PasswordStore<Peer>, buf: Vec<u8>) -> Option<(session::Session, Option<&'a Peer>)> {
    let packet = Packet { raw: buf };

    // Check it is an Hello/RepeatHello packet
    match packet.session_state() {
        Ok(SessionState::Hello) | Ok(SessionState::RepeatHello) => (),
        _ => return None,
    };

    let session = session::Session::new(my_perm_pk, my_perm_sk, keys::PublicKey::new_from_bytes(&packet.sender_perm_pub_key()));
    let peer = password_store.get_peer(&packet.sender_encrypted_temp_pub_key());

    Some((session, peer))
}
