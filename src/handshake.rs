//! Creates and reads CryptoAuth Hello packets
use cryptography::{crypto_box, hash_password, open_packet_end};
use keys;
use authentication;
use session::{Session, SessionState};
use handshake_packet::{HandshakePacket, HandshakePacketBuilder, HandshakePacketType};
use passwords::PasswordStore;

/// Implements Hello packet creation, as defined by
/// https://github.com/fc00/spec/blob/10b349ab11/cryptoauth.md#hello-repeathello
///
/// # Examples
///
/// ```
/// use fcp_cryptoauth::cryptography::crypto_box::{gen_keypair, PublicKey};
/// use fcp_cryptoauth::authentication::AuthChallenge;
/// use fcp_cryptoauth::session::Session;
/// use fcp_cryptoauth::keys::FromBase32;
/// use fcp_cryptoauth::handshake::create_next_handshake_packet;
///
/// let (my_pk, my_sk) = gen_keypair();
/// let their_pk = PublicKey::from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
/// // Corresponding secret key: 824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8
/// let mut session = Session::new(true, my_pk, my_sk, their_pk);
///
/// let login = "foo".to_owned().into_bytes();
/// let password = "bar".to_owned().into_bytes();
/// let challenge = AuthChallenge::LoginPassword { login: login, password: password };
///
/// let hello = create_next_handshake_packet(&mut session, challenge);
/// let bytes = hello.raw;
/// println!("{:?}", bytes);
/// ```
pub fn create_next_handshake_packet(session: &mut Session, auth_challenge: authentication::AuthChallenge) -> HandshakePacket {
    /////////////////////////////////////
    // Paragraph 1
    let random_nonce = match session.handshake_nonce {
        Some(nonce) => nonce,
        None => {
            // TODO: reset the nonce if the connection is reset.
            let nonce = crypto_box::gen_nonce();
            session.handshake_nonce = Some(nonce);
            nonce
        }
    };

    /////////////////////////////////////
    // Paragraph 2
    let sender_perm_pub_key = session.my_perm_pk.0;

    /////////////////////////////////////
    // Paragraph 3
    let shared_secret = match auth_challenge {
        authentication::AuthChallenge::None => unimplemented!(), // TODO
        authentication::AuthChallenge::Password { ref password } |
        authentication::AuthChallenge::LoginPassword { ref password, login: _ } => {
            hash_password(password, &session.my_perm_sk, &session.their_perm_pk)
        }
    };
    if let Some(known_secret) = session.shared_secret {
        assert_eq!(known_secret, shared_secret);
    }
    else {
        use hex::ToHex;
        println!("Got secret: {}", shared_secret.to_vec().to_hex());
        session.shared_secret = Some(shared_secret);
    }

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
            &session.my_temp_pk.0, // We encrypt the temp pub key
            &random_nonce, // with the Nonce
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
    let packet_type = match session.state {
        SessionState::Uninitialized  => HandshakePacketType::Hello,
        SessionState::ReceivedHello  => HandshakePacketType::Key,
        SessionState::SentHello      => HandshakePacketType::RepeatHello,
        SessionState::SentKey        => HandshakePacketType::RepeatKey,
        SessionState::Established(_) => panic!("Trying to sent handshake packet, but session is established"),
    };
    use hex::ToHex;
    println!("Creating {:?} with secret {} and nonce {}", packet_type, shared_secret.to_vec().to_hex(), random_nonce.0.to_vec().to_hex());
    let packet = HandshakePacketBuilder::new()
            .packet_type(&packet_type)
            .auth_challenge(&auth_challenge.to_bytes(session))
            .random_nonce(&random_nonce.0)
            .sender_perm_pub_key(&sender_perm_pub_key)
            .msg_auth_code(&msg_auth_code)
            .sender_encrypted_temp_pub_key(&my_encrypted_temp_pk)
            .finalize().unwrap();

    /////////////////////////////////////
    // Update the session state
    session.state = match session.state {
        SessionState::Uninitialized  => SessionState::SentHello,
        SessionState::ReceivedHello  => SessionState::SentKey,
        SessionState::SentHello      => SessionState::Established(5),
        SessionState::SentKey        => SessionState::Established(5),
        SessionState::Established(_) => panic!("The impossible happened."),
    };
    packet
}

/// Read a network packet, assumed to be an Hello or a RepeatHello.
///
/// TODO: improve error return
pub fn parse_handshake_packet<'a, Peer: Clone>(session: &mut Session, password_store: &'a PasswordStore<Peer>, packet: &HandshakePacket) -> Option<&'a Peer> {
    // Check the packet type vs session state
    match packet.packet_type() {
        Err(_) => panic!("Non-handshake packet passed to parse_handshake_packet"),
        _ => (),
    };

    let mut hash_code = [0u8; 7];
    hash_code.copy_from_slice(&packet.auth_challenge()[1..8]);
    let candidates_opt = match packet.auth_challenge()[0] {
        0x00 => return None, // No auth, not supported.
        0x01 => { // Password only
            password_store.get_candidate_peers_from_password_doublehash_slice(&hash_code)
        }
        0x02 => { // Login + Password
            password_store.get_candidate_peers_from_login_hash_slice(&hash_code)
        }
        _ => return None, // Unknown auth type
    };
    let candidates = match candidates_opt {
        Some(candidates) => candidates,
        None => return None,
    };
            

    let their_perm_pk = crypto_box::PublicKey::from_slice(&packet.sender_perm_pub_key()).unwrap();
    if session.their_perm_pk != their_perm_pk {
        // Wrong key. Drop the packet.
        return None;
    }

    for &(ref password, ref peer) in candidates {
        let nonce = crypto_box::Nonce::from_slice(&packet.random_nonce()).unwrap();
        let shared_secret = match session.shared_secret {
            None => hash_password(password, &session.my_perm_sk, &their_perm_pk),
            Some(ss) => ss,
        };
        let shared_secret_key = crypto_box::PrecomputedKey::from_slice(&shared_secret).unwrap();
        let packet_end = open_packet_end(packet.sealed_data(), &shared_secret_key, &nonce);
        if let Some((their_temp_pk, data)) = packet_end {
            session.state = match packet.packet_type() {
                Ok(HandshakePacketType::Hello) | Ok(HandshakePacketType::RepeatHello) =>
                        SessionState::ReceivedHello,
                Ok(HandshakePacketType::Key) | Ok(HandshakePacketType::RepeatKey) =>
                        SessionState::Established(4),
                Err(_) => panic!("The impossible happened."),
            };
            session.shared_secret = Some(shared_secret);
            session.their_temp_pk = Some(their_temp_pk);
            session.handshake_nonce = Some(nonce);
            return Some(peer)
        }
    };
    None
}

#[test]
fn test_parse_handshake_password() {
    use hex::FromHex as VecFromHex;
    use keys::{FromBase32, FromHex};

    let my_sk = crypto_box::SecretKey::from_hex(b"ac3e53b518e68449692b0b2f2926ef2fdc1eac5b9dbd10a48114263b8c8ed12e").unwrap();
    let my_pk = crypto_box::PublicKey::from_base32(b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k").unwrap();
    let their_pk = crypto_box::PublicKey::from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
    // Corresponding secret key: 824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8
    let mut session = Session::new(true, my_pk, my_sk, their_pk);

    let raw = Vec::from_hex("0000000101ed58a609bc994800000000551ae6bc4940ff2e1f4e9cba228ebe0a18ed77a2ee0a7bb10286fe4b2c3e74fe4f5ceb2f524c81fabe8a94fa41daa65394900f53079d0a1497cdd55def51daf65a45027745706d1673d7a3c8946fa043923e46772284475b26ea71f504055537547c4276d92a013740ab42c612516c69ad8b524d11b55eff7f8976512248806104f0ec4f3e62f8f40926af4cfcad7e79").unwrap();
    let packet = HandshakePacket { raw: raw };
    let mut store = PasswordStore::new(session.my_perm_sk.clone());
    store.add_peer(&"foo".as_bytes().to_vec(), "bar".as_bytes().to_vec(), &session.their_perm_pk, "my friend".to_owned());

    assert_eq!(packet.sender_perm_pub_key(), session.their_perm_pk.0);
    match parse_handshake_packet(&mut session, &store, &packet) {
        None => assert!(false),
        Some(peer) => assert_eq!(peer, &"my friend".to_owned()),
    }
}

#[test]
fn test_parse_handshake_login() {
    use hex::FromHex as VecFromHex;
    use keys::{FromBase32, FromHex};

    let my_sk = crypto_box::SecretKey::from_hex(b"ac3e53b518e68449692b0b2f2926ef2fdc1eac5b9dbd10a48114263b8c8ed12e").unwrap();
    let my_pk = crypto_box::PublicKey::from_base32(b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k").unwrap();
    let their_pk = crypto_box::PublicKey::from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
    // Corresponding secret key: 824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8
    let mut session = Session::new(true, my_pk, my_sk, their_pk);

    let raw = Vec::from_hex("000000010226b46b68ffc68f00000000172d7a21645efff9ef874a9094351e870f622537ea208e7f0286fe4b2c3e74fe4f5ceb2f524c81fabe8a94fa41daa65394900f53079d0a14aa670e527964f576521d63c72b1398c19438ea7b661c7dec59e67b86bddf128705108782d53d22742a6b5d2baa6b23af26e154f87678322f0e43eea7a82563e655c36d6126881ec44d0e44ba659c21cafdb3a8017c4ccdc7").unwrap();
    let packet = HandshakePacket { raw: raw };
    let mut store = PasswordStore::new(session.my_perm_sk.clone());
    store.add_peer(&"foo".as_bytes().to_vec(), "bar".as_bytes().to_vec(), &session.their_perm_pk, "my friend".to_owned());

    assert_eq!(packet.sender_perm_pub_key(), session.their_perm_pk.0);
    match parse_handshake_packet(&mut session, &store, &packet) {
        None => assert!(false),
        Some(peer) => assert_eq!(peer, &"my friend".to_owned()),
    }
}