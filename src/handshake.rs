//! Creates and reads CryptoAuth Hello packets
use cryptography::{crypto_box, open_packet_end, shared_secret_from_password, shared_secret_from_keys};
use cryptography::crypto_box::{PublicKey, SecretKey, PrecomputedKey, Nonce};
use keys;
use authentication::{AuthChallenge, AuthFailure};
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
/// use fcp_cryptoauth::session::{Session, SessionState};
/// use fcp_cryptoauth::keys::FromBase32;
/// use fcp_cryptoauth::handshake::create_next_handshake_packet;
///
/// let (my_pk, my_sk) = gen_keypair();
/// let their_pk = PublicKey::from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
/// // Corresponding secret key: 824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8
/// let mut session = Session::new(my_pk, my_sk, their_pk, SessionState::UninitializedKnownPeer);
///
/// let login = "foo".to_owned().into_bytes();
/// let password = "bar".to_owned().into_bytes();
/// let challenge = AuthChallenge::LoginPassword { login: login, password: password };
///
/// let hello = create_next_handshake_packet(&mut session, &challenge);
/// let bytes = hello.raw;
/// println!("{:?}", bytes);
/// ```
pub fn create_next_handshake_packet(session: &mut Session, challenge: &AuthChallenge) -> HandshakePacket {
    let (packet, new_session_state) = match session.state.clone() { // TODO: do not clone
        SessionState::UninitializedUnknownPeer => {
            panic!("Trying to send a packet to a totally unknown peer. We need at least a Challenge or a PasswordStore to do that.")
        },
        SessionState::UninitializedKnownPeer => {
            // If we have not sent or received anything yet, send Hello
            // and set the state to SentHello.
            let handshake_nonce = crypto_box::gen_nonce();
            let shared_secret_key = challenge.make_shared_secret_key(session);
            let packet = create_hello(session, &handshake_nonce, &challenge, false);
            let state = SessionState::SentHello {
                handshake_nonce: handshake_nonce,
                shared_secret_key: shared_secret_key,
                };
            (packet, state)
        },
        SessionState::SentHello { handshake_nonce, shared_secret_key } => {
            // If we already sent Hello but nothing else, and not received
            // anything, repeat the Hello and keep the state unchanged.
            let shared_secret_key = challenge.make_shared_secret_key(session);
            let packet = create_hello(session, &handshake_nonce, &challenge, true);
            let state = SessionState::SentHello {
                handshake_nonce: handshake_nonce,
                shared_secret_key: shared_secret_key,
                };
            (packet, state)
        },
        SessionState::ReceivedHello { their_temp_pk, handshake_nonce, shared_secret_key } => {
            // If we received an Hello but nothing else, and did not
            // send any reply to the Hello, send Key and set the state
            // to SentKey
            let packet = create_key(session, &their_temp_pk, &handshake_nonce, &shared_secret_key, false);
            let state = SessionState::SentKey {
                their_temp_pk: their_temp_pk,
                handshake_nonce: handshake_nonce,
                shared_secret_key: shared_secret_key,
                };
            (packet, state)
        },
        SessionState::SentKey { their_temp_pk, handshake_nonce, shared_secret_key } => {
            // If we received an Hello but nothing else, and did not send
            // anything other than key, repeat Key and keep the state
            // unchanged.
            let packet = create_key(session, &their_temp_pk, &handshake_nonce, &shared_secret_key, true);
            let state = SessionState::SentKey {
                their_temp_pk: their_temp_pk,
                handshake_nonce: handshake_nonce,
                shared_secret_key: shared_secret_key,
                };
            (packet, state)
        },
        SessionState::Established { .. } => {
            panic!("Tried to create an handshake packet for an established session.")
        },
    };
    session.state = new_session_state;
    packet
}

/// Creates an Hello packet
fn create_hello(
        session: &Session,
        nonce: &crypto_box::Nonce,
        challenge: &AuthChallenge,
        repeat: bool
        ) -> HandshakePacket {

    let packet_type = if repeat {
        HandshakePacketType::RepeatHello
    }
    else {
        HandshakePacketType::Hello
    };

    let shared_secret_key = challenge.make_shared_secret_key(session);
    let (msg_auth_code, my_encrypted_temp_pk) = create_msg_end(session, nonce, &shared_secret_key);

    let packet = HandshakePacketBuilder::new()
            .packet_type(&packet_type)
            .auth_challenge(&challenge.to_bytes(session))
            .random_nonce(&nonce.0)
            .sender_perm_pub_key(&session.my_perm_pk.0)
            .msg_auth_code(&msg_auth_code)
            .sender_encrypted_temp_pub_key(&my_encrypted_temp_pk)
            .finalize().unwrap();
    packet
}

/// Creates a Key packet
fn create_key(
        session: &Session,
        their_temp_pk: &PublicKey,
        nonce: &Nonce,
        shared_secret_key: &PrecomputedKey,
        repeat: bool
        ) -> HandshakePacket {

    let packet_type = if repeat {
        HandshakePacketType::RepeatKey
    }
    else {
        HandshakePacketType::Key
    };

    let (msg_auth_code, my_encrypted_temp_pk) = create_msg_end(session, nonce, shared_secret_key);

    let packet = HandshakePacketBuilder::new()
            .packet_type(&packet_type)
            .auth_challenge(&AuthChallenge::None.to_bytes(session))
            .random_nonce(&nonce.0)
            .sender_perm_pub_key(&session.my_perm_pk.0)
            .msg_auth_code(&msg_auth_code)
            .sender_encrypted_temp_pub_key(&my_encrypted_temp_pk)
            .finalize().unwrap();
    packet
}

/// Returns the msg_auth_code and sender_encrypted_temp_pk fields
/// of a packet.
fn create_msg_end(session: &Session, nonce: &Nonce, shared_secret_key: &PrecomputedKey)
        -> ([u8; crypto_box::MACBYTES], [u8; crypto_box::PUBLICKEYBYTES]) {
    use hex::ToHex;
    println!("Encrypting temp pk {} with nonce {} and secret {}",
            session.my_temp_pk.0.to_vec().to_hex(),
            nonce.0.to_vec().to_hex(),
            shared_secret_key.0.to_vec().to_hex());
    // This part is a bit tricky. Hold on tight.

    // Here, we will encrypt the temp pub *key* using the *shared secret*.
    // This may seem counter-intuitive; but it is actually valid because
    // encryption keys and symmetric secrets all are 32-bits long.
    let authenticated_sealed_temp_pk = crypto_box::seal_precomputed(
            &session.my_temp_pk.0, // We encrypt the temp pub key
            &nonce, // with the Nonce
            &shared_secret_key, // using the shared secret.
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

    (msg_auth_code, my_encrypted_temp_pk)
}


/// Read a network packet, assumed to be an Hello or a RepeatHello.
///
/// TODO: improve error return
pub fn parse_handshake_packet<'a, Peer: Clone>(
        session: &mut Session,
        password_store: &'a PasswordStore<Peer>,
        packet: &HandshakePacket,
        ) -> Result<(&'a Peer, Vec<u8>), AuthFailure> {
    let packet_type = match packet.packet_type() {
        Err(_) => panic!("Non-handshake packet passed to parse_handshake_packet"),
        Ok(packet_type) => packet_type,
    };

    let (shared_secret_key, their_temp_pk, nonce, peer, data) = 
            try!(authenticate_packet_author(session, password_store, packet));
    // Below, we are sure this packet is from this peer.
    session.state = update_session_state_on_received_packet(
            session, packet, &packet_type, shared_secret_key, their_temp_pk, nonce,
            password_store);
    Ok((peer, data))
}


// Should only be called for authenticated packets.
fn update_session_state_on_received_packet<Peer: Clone>(
        session: &mut Session,
        packet: &HandshakePacket,
        packet_type: &HandshakePacketType,
        shared_secret_key: PrecomputedKey,
        their_temp_pk: PublicKey,
        nonce: Nonce,
        password_store: &PasswordStore<Peer>,
        ) -> SessionState {
    match *packet_type {
        HandshakePacketType::Hello | HandshakePacketType::RepeatHello => {
            update_session_state_on_received_hello(
                    session, packet, shared_secret_key, their_temp_pk, nonce,
                    password_store)
        }
        HandshakePacketType::Key | HandshakePacketType::RepeatKey => {
            update_session_state_on_received_key(
                    session, packet, shared_secret_key, their_temp_pk, nonce,
                    password_store)
        }
    }
}

// Should only be called for authenticated packets.
fn update_session_state_on_received_hello<Peer: Clone>(
        session: &mut Session,
        packet: &HandshakePacket,
        shared_secret_key: PrecomputedKey,
        their_temp_pk: PublicKey,
        nonce: Nonce,
        password_store: &PasswordStore<Peer>,
        ) -> SessionState {
    // This function is a huge case disjunction. I am very sorry if you
    // have to read this, but we have to do it at some point.
    assert!(packet.packet_type() == Ok(HandshakePacketType::Hello) ||
            packet.packet_type() == Ok(HandshakePacketType::RepeatHello));
    use hex::ToHex;
    println!("My perm pk: {}", session.my_perm_pk.0.to_vec().to_hex());
    println!("My temp pk: {}", session.my_temp_pk.0.to_vec().to_hex());
    match session.state.clone() { // TODO: do not clone
        SessionState::SentHello { handshake_nonce, shared_secret_key } => {
            // We both sent a hello. Break the tie by making the
            // one with the lower key win.
            if session.my_perm_pk < session.their_perm_pk {
                // I win. Keep my hello.
                SessionState::SentHello {
                    handshake_nonce: nonce, // XXX: should we use the other peer's nonce?
                    shared_secret_key: shared_secret_key,
                    }
            }
            else {
                // They win. Keep theirs
                session.reset();
                SessionState::ReceivedHello {
                    their_temp_pk: their_temp_pk,
                    handshake_nonce: nonce, // Important! We use *their* nonce and discard ours
                    shared_secret_key: shared_secret_from_keys(
                            &session.my_perm_sk, &their_temp_pk),
                    }
            }
        },
        SessionState::UninitializedUnknownPeer => {
            SessionState::ReceivedHello {
                their_temp_pk: their_temp_pk,
                handshake_nonce: nonce,
                shared_secret_key: shared_secret_from_keys(
                        &session.my_perm_sk, &their_temp_pk),
                }
        },
        SessionState::UninitializedKnownPeer { .. } |
        SessionState::ReceivedHello { .. } |
        SessionState::SentKey { .. } |
        SessionState::Established { .. } => {
            // Reset the session
            session.reset();
            SessionState::ReceivedHello {
                their_temp_pk: their_temp_pk,
                handshake_nonce: nonce,
                shared_secret_key: shared_secret_from_keys(
                        &session.my_perm_sk, &their_temp_pk),
                }
        },
    }
}

// Should only be called for authenticated packets.
fn update_session_state_on_received_key<Peer: Clone>(
        session: &Session,
        packet: &HandshakePacket,
        shared_secret_key: PrecomputedKey,
        their_temp_pk: PublicKey,
        nonce: Nonce,
        password_store: &PasswordStore<Peer>,
        ) -> SessionState {
    assert!(packet.packet_type() == Ok(HandshakePacketType::Key) ||
            packet.packet_type() == Ok(HandshakePacketType::RepeatKey));
    match session.state.clone() { // TODO: do not clone
        SessionState::SentHello { handshake_nonce, shared_secret_key } => {
            let mut nonce = [0u8; crypto_box::NONCEBYTES];
            nonce[crypto_box::NONCEBYTES-1] = 4u8;
            let nonce = Nonce::from_slice(&nonce);
            SessionState::Established {
                nonce: nonce.unwrap(),
                their_temp_pk: their_temp_pk,
                shared_secret_key: shared_secret_from_keys(
                        &session.my_temp_sk, &their_temp_pk),
                }
        },
        SessionState::UninitializedUnknownPeer |
        SessionState::UninitializedKnownPeer { .. } |
        SessionState::ReceivedHello { .. } |
        SessionState::SentKey { .. } |
        SessionState::Established { .. } => {
            // We did not expect a Key. Keep the session unchanged
            session.state.clone() // TODO: do not clone
        },
    }
}

/// Tries to authenticate the author of the packet against the
/// `password_store`. If authentication was successful, returns
/// `Some((shared_secret_key, their_temp_pk, peer, data))`
fn authenticate_packet_author<'a, Peer: Clone>(
        session: &Session,
        password_store: &'a PasswordStore<Peer>,
        packet: &HandshakePacket,
        ) -> Result<(PrecomputedKey, PublicKey, Nonce, &'a Peer, Vec<u8>), AuthFailure> { 
    let mut hash_code = [0u8; 7];
    hash_code.copy_from_slice(&packet.auth_challenge()[1..8]);
    let candidates_opt = match packet.auth_challenge()[0] {
        0x00 => return Err(AuthFailure::AuthNone), // No auth, not supported.
        0x01 => { // Password only
            password_store.get_candidate_peers_from_password_doublehash_slice(&hash_code)
        }
        0x02 => { // Login + Password
            password_store.get_candidate_peers_from_login_hash_slice(&hash_code)
        }
        method => return Err(AuthFailure::UnknownAuthMethod(method)),
    };
    let candidates = match candidates_opt {
        Some(candidates) => candidates,
        None => return Err(AuthFailure::InvalidCredentials),
    };

    let their_perm_pk = crypto_box::PublicKey::from_slice(&packet.sender_perm_pub_key()).unwrap();
    if session.their_perm_pk != their_perm_pk {
        // Wrong key. Drop the packet.
        return Err(AuthFailure::WrongPublicKey);
    }

    for &(ref password, ref peer) in candidates {
        let nonce = crypto_box::Nonce::from_slice(&packet.random_nonce()).unwrap();
        let shared_secret = shared_secret_from_password(
                password, &session.my_perm_sk, &their_perm_pk);
        let shared_secret_key = PrecomputedKey::from_slice(&shared_secret).unwrap();
        let packet_end = open_packet_end(packet.sealed_data(), &shared_secret_key, &nonce);
        if let Some((their_temp_pk, data)) = packet_end {
            return Ok((shared_secret_key, their_temp_pk, nonce, peer, data))
        }
    };
    Err(AuthFailure::InvalidCredentials)
}

#[test]
fn test_parse_handshake_password() {
    use hex::FromHex as VecFromHex;
    use keys::{FromBase32, FromHex};

    let my_sk = crypto_box::SecretKey::from_hex(b"ac3e53b518e68449692b0b2f2926ef2fdc1eac5b9dbd10a48114263b8c8ed12e").unwrap();
    let my_pk = crypto_box::PublicKey::from_base32(b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k").unwrap();
    let their_pk = crypto_box::PublicKey::from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
    // Corresponding secret key: 824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8
    let mut session = Session::new(my_pk, my_sk, their_pk, SessionState::UninitializedUnknownPeer);

    let raw = Vec::from_hex("0000000101ed58a609bc994800000000551ae6bc4940ff2e1f4e9cba228ebe0a18ed77a2ee0a7bb10286fe4b2c3e74fe4f5ceb2f524c81fabe8a94fa41daa65394900f53079d0a1497cdd55def51daf65a45027745706d1673d7a3c8946fa043923e46772284475b26ea71f504055537547c4276d92a013740ab42c612516c69ad8b524d11b55eff7f8976512248806104f0ec4f3e62f8f40926af4cfcad7e79").unwrap();
    let packet = HandshakePacket { raw: raw };
    let mut store = PasswordStore::new(session.my_perm_sk.clone());
    store.add_peer(&"foo".as_bytes().to_vec(), "bar".as_bytes().to_vec(), &session.their_perm_pk, "my friend".to_owned());

    assert_eq!(packet.sender_perm_pub_key(), session.their_perm_pk.0);
    match parse_handshake_packet(&mut session, &store, &packet) {
        Err(_) => assert!(false),
        Ok((peer, _data)) => assert_eq!(peer, &"my friend".to_owned()),
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
    let mut session = Session::new(my_pk, my_sk, their_pk, SessionState::UninitializedUnknownPeer);

    let raw = Vec::from_hex("000000010226b46b68ffc68f00000000172d7a21645efff9ef874a9094351e870f622537ea208e7f0286fe4b2c3e74fe4f5ceb2f524c81fabe8a94fa41daa65394900f53079d0a14aa670e527964f576521d63c72b1398c19438ea7b661c7dec59e67b86bddf128705108782d53d22742a6b5d2baa6b23af26e154f87678322f0e43eea7a82563e655c36d6126881ec44d0e44ba659c21cafdb3a8017c4ccdc7").unwrap();
    let packet = HandshakePacket { raw: raw };
    let mut store = PasswordStore::new(session.my_perm_sk.clone());
    store.add_peer(&"foo".as_bytes().to_vec(), "bar".as_bytes().to_vec(), &session.their_perm_pk, "my friend".to_owned());

    assert_eq!(packet.sender_perm_pub_key(), session.their_perm_pk.0);
    match parse_handshake_packet(&mut session, &store, &packet) {
        Err(_) => assert!(false),
        Ok((peer, _data)) => assert_eq!(peer, &"my friend".to_owned()),
    }
}
