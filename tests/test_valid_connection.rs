extern crate fcp_cryptoauth;

use std::collections::HashMap;

use fcp_cryptoauth::wrapper::*;

fn arr_to_vec(s: &[u8]) -> Vec<u8> {
    s.to_owned().to_vec()
}

#[test]
fn loginpassword_noreciprocal_noupkeep_nopiggyback() {
    init();

    let peer1_credentials = Credentials::LoginPassword {
        login: arr_to_vec(b"login"),
        password: arr_to_vec(b"pass"),
    };
    let mut peer2_allowed_credentials = HashMap::new();
    peer2_allowed_credentials.insert(peer1_credentials.clone(), "peer1");

    let (peer1_pk, peer1_sk) = gen_keypair();
    let (peer2_pk, peer2_sk) = gen_keypair();

    let mut peer1 = Wrapper::new_outgoing_connection(
            peer1_pk, peer1_sk, peer2_pk, peer1_credentials, None, ());

    assert_eq!(peer1.connection_state(), ConnectionState::Uninitialized);

    // Hello from 1 to 2.

    let mut packets = peer1.wrap_message(&arr_to_vec(b"should not be sent (1)"));
    assert_eq!(packets.len(), 1);
    let packet = packets.remove(0);

    let (mut peer2, messages) = Wrapper::new_incoming_connection(
            peer2_pk, peer2_sk, Credentials::None, peer2_allowed_credentials, packet).unwrap();
    assert_eq!(messages, vec![]); // peer1 used wrap_message,there must be no piggy-backed data
    assert_eq!(peer1.connection_state(), ConnectionState::Handshake);
    assert_eq!(peer2.connection_state(), ConnectionState::Handshake);

    // Key from 2 to 1.

    let mut packets = peer2.wrap_message(&arr_to_vec(b"should not be sent (2)"));
    assert_eq!(packets.len(), 1);
    let packet = packets.remove(0);

    let messages = peer1.unwrap_message(packet).unwrap();

    assert_eq!(messages, Vec::<Vec<u8>>::new()); // peer2 used wrap_message,there must be no piggy-backed data
    assert_eq!(peer1.connection_state(), ConnectionState::Established);
    assert_eq!(peer2.connection_state(), ConnectionState::Handshake);

    // Regular packet from 1 to 2

    let mut packets = peer1.wrap_message(&arr_to_vec(b"should be sent (3)"));
    assert_eq!(packets.len(), 1);
    let packet = packets.remove(0);

    let expected_nonce = [0u8, 0u8, 0u8, 4u8];
    assert_eq!(packet[0..4], expected_nonce);

    let messages = peer2.unwrap_message(packet).unwrap();

    assert_eq!(messages, vec![arr_to_vec(b"should be sent (3)")]);
    assert_eq!(peer1.connection_state(), ConnectionState::Established);
    assert_eq!(peer2.connection_state(), ConnectionState::Established);

    // Regular packet from 2 to 1

    let mut packets = peer2.wrap_message(&arr_to_vec(b"should be sent (4)"));
    assert_eq!(packets.len(), 1);
    let packet = packets.remove(0);

    let expected_nonce = [0u8, 0u8, 0u8, 4u8];
    assert_eq!(packet[0..4], expected_nonce);

    let messages = peer1.unwrap_message(packet).unwrap();

    assert_eq!(messages, vec![arr_to_vec(b"should be sent (4)")]);
    assert_eq!(peer1.connection_state(), ConnectionState::Established);
    assert_eq!(peer2.connection_state(), ConnectionState::Established);
}

#[test]
fn password_noreciprocal_noupkeep_nopiggyback() {
    init();

    let peer1_credentials = Credentials::Password {
        password: arr_to_vec(b"pass"),
    };
    let mut peer2_allowed_credentials = HashMap::new();
    peer2_allowed_credentials.insert(peer1_credentials.clone(), "peer1");

    let (peer1_pk, peer1_sk) = gen_keypair();
    let (peer2_pk, peer2_sk) = gen_keypair();

    let mut peer1 = Wrapper::new_outgoing_connection(
            peer1_pk, peer1_sk, peer2_pk, peer1_credentials, None, ());

    assert_eq!(peer1.connection_state(), ConnectionState::Uninitialized);

    // Hello from 1 to 2.

    let mut packets = peer1.wrap_message(&arr_to_vec(b"should not be sent (1)"));
    assert_eq!(packets.len(), 1);
    let packet = packets.remove(0);

    let (mut peer2, messages) = Wrapper::new_incoming_connection(
            peer2_pk, peer2_sk, Credentials::None, peer2_allowed_credentials, packet).unwrap();
    assert_eq!(messages, vec![]); // peer1 used wrap_message,there must be no piggy-backed data
    assert_eq!(peer1.connection_state(), ConnectionState::Handshake);
    assert_eq!(peer2.connection_state(), ConnectionState::Handshake);

    // Key from 2 to 1.

    let mut packets = peer2.wrap_message(&arr_to_vec(b"should not be sent (2)"));
    assert_eq!(packets.len(), 1);
    let packet = packets.remove(0);

    let messages = peer1.unwrap_message(packet).unwrap();

    assert_eq!(messages, Vec::<Vec<u8>>::new()); // peer2 used wrap_message,there must be no piggy-backed data
    assert_eq!(peer1.connection_state(), ConnectionState::Established);
    assert_eq!(peer2.connection_state(), ConnectionState::Handshake);

    // Regular packet from 1 to 2

    let mut packets = peer1.wrap_message(&arr_to_vec(b"should be sent (3)"));
    assert_eq!(packets.len(), 1);
    let packet = packets.remove(0);

    let expected_nonce = [0u8, 0u8, 0u8, 4u8];
    assert_eq!(packet[0..4], expected_nonce);

    let messages = peer2.unwrap_message(packet).unwrap();

    assert_eq!(messages, vec![arr_to_vec(b"should be sent (3)")]);
    assert_eq!(peer1.connection_state(), ConnectionState::Established);
    assert_eq!(peer2.connection_state(), ConnectionState::Established);

    // Regular packet from 2 to 1

    let mut packets = peer2.wrap_message(&arr_to_vec(b"should be sent (4)"));
    assert_eq!(packets.len(), 1);
    let packet = packets.remove(0);

    let expected_nonce = [0u8, 0u8, 0u8, 4u8];
    assert_eq!(packet[0..4], expected_nonce);

    let messages = peer1.unwrap_message(packet).unwrap();

    assert_eq!(messages, vec![arr_to_vec(b"should be sent (4)")]);
    assert_eq!(peer1.connection_state(), ConnectionState::Established);
    assert_eq!(peer2.connection_state(), ConnectionState::Established);
}

// Will be run with (peerA, peerB) and (peerB, peerA)
fn loginpassword_reciprocal_noupkeep_nopiggyback_aux(peer1_pk: PublicKey, peer1_sk: SecretKey, peer2_pk: PublicKey, peer2_sk: SecretKey) {
    let credentials = Credentials::LoginPassword {
        login: arr_to_vec(b"login"),
        password: arr_to_vec(b"pass"),
    };
    let mut allowed_credentials = HashMap::new();
    allowed_credentials.insert(credentials.clone(), "peer1");

    let mut peer1 = Wrapper::new_outgoing_connection(
            peer1_pk, peer1_sk, peer2_pk, credentials.clone(), Some(allowed_credentials.clone()), "peer2 (of peer1)");
    let mut peer2 = Wrapper::new_outgoing_connection(
            peer2_pk, peer2_sk, peer1_pk, credentials, Some(allowed_credentials), "peer2 (of peer1)");

    assert_eq!(peer1.connection_state(), ConnectionState::Uninitialized);

    // Hello

    let mut packets = peer1.wrap_message(&arr_to_vec(b"should not be sent (1 1)"));
    assert_eq!(packets.len(), 1);
    let packet1 = packets.remove(0);

    let mut packets = peer2.wrap_message(&arr_to_vec(b"should not be sent (1 2)"));
    assert_eq!(packets.len(), 1);
    let packet2 = packets.remove(0);

    let messages = peer2.unwrap_message(packet1).unwrap();
    assert_eq!(messages, Vec::<Vec<u8>>::new()); // peer1 used wrap_message,there must be no piggy-backed data
    let messages = peer1.unwrap_message(packet2).unwrap();
    assert_eq!(messages, Vec::<Vec<u8>>::new()); // peer2 used wrap_message,there must be no piggy-backed data
    assert_eq!((peer1.connection_state(), peer2.connection_state()), (ConnectionState::Handshake, ConnectionState::Handshake));

    // Keys

    let mut packets1 = peer1.wrap_message(&arr_to_vec(b"should not be sent (2 1)"));
    let mut packets2 = peer2.wrap_message(&arr_to_vec(b"should not be sent (2 2)"));

    assert_eq!(packets1.len()+packets2.len(), 1); // The loser sends key, the winner stays quiet
    if packets1.len() == 1 {
        let packet1 = packets1.remove(0);
        assert_eq!(packet1[3], 2);
        let messages1 = peer2.unwrap_message(packet1).unwrap();
        assert_eq!(messages1, Vec::<Vec<u8>>::new()); // peer2 used wrap_message,there must be no piggy-backed data
        assert_eq!(peer1.connection_state(), ConnectionState::Handshake);
        assert_eq!(peer2.connection_state(), ConnectionState::Established);
    }
    else if packets2.len() == 1 {
        let packet2 = packets2.remove(0);
        assert_eq!(packet2[3], 2);
        let messages2 = peer1.unwrap_message(packet2).unwrap();
        assert_eq!(messages2, Vec::<Vec<u8>>::new()); // peer1 used wrap_message,there must be no piggy-backed data
        assert_eq!(peer2.connection_state(), ConnectionState::Handshake);
        assert_eq!(peer1.connection_state(), ConnectionState::Established);
    }
    else {
        assert!(false)
    }

    if peer1.connection_state() == ConnectionState::Established {
        // Regular packet from 1 to 2

        let mut packets = peer1.wrap_message(&arr_to_vec(b"should be sent (3)"));
        assert_eq!(packets.len(), 1);
        let packet = packets.remove(0);

        let expected_nonce = [0u8, 0u8, 0u8, 4u8];
        assert_eq!(packet[0..4], expected_nonce);

        let messages = peer2.unwrap_message(packet).unwrap();

        assert_eq!(messages, vec![arr_to_vec(b"should be sent (3)")]);
        assert_eq!(peer1.connection_state(), ConnectionState::Established);
        assert_eq!(peer2.connection_state(), ConnectionState::Established);

        // Regular packet from 2 to 1

        let mut packets = peer2.wrap_message(&arr_to_vec(b"should be sent (4)"));
        assert_eq!(packets.len(), 1);
        let packet = packets.remove(0);

        let expected_nonce = [0u8, 0u8, 0u8, 4u8];
        assert_eq!(packet[0..4], expected_nonce);

        let messages = peer1.unwrap_message(packet).unwrap();

        assert_eq!(messages, vec![arr_to_vec(b"should be sent (4)")]);
        assert_eq!(peer1.connection_state(), ConnectionState::Established);
        assert_eq!(peer2.connection_state(), ConnectionState::Established);
    }
}
#[test]
fn loginpassword_reciprocal_noupkeep_nopiggyback() {
    init();

    let (peer_a_pk, peer_a_sk) = gen_keypair();
    let (peer_b_pk, peer_b_sk) = gen_keypair();


    loginpassword_reciprocal_noupkeep_nopiggyback_aux(peer_a_pk, peer_a_sk.clone(), peer_b_pk.clone(), peer_b_sk.clone());
    loginpassword_reciprocal_noupkeep_nopiggyback_aux(peer_b_pk, peer_b_sk, peer_a_pk, peer_a_sk);
}

#[test]
fn authnone() {
    init();

    let peer1_credentials = Credentials::LoginPassword {
        login: arr_to_vec(b"login"),
        password: arr_to_vec(b"pass"),
    };
    let mut peer2_allowed_credentials = HashMap::new();
    peer2_allowed_credentials.insert(peer1_credentials.clone(), "peer1");

    let (peer1_pk, peer1_sk) = gen_keypair();
    let (peer2_pk, peer2_sk) = gen_keypair();

    let mut peer1 = Wrapper::new_outgoing_connection(
            peer1_pk, peer1_sk, peer2_pk, peer1_credentials, None, ());

    assert_eq!(peer1.connection_state(), ConnectionState::Uninitialized);

    // Hello from 1 to 2.

    let mut packets = peer1.wrap_message(&arr_to_vec(b"should not be sent (1)"));
    assert_eq!(packets.len(), 1);
    let mut packet = packets.remove(0);

    // Set the auth to None
    assert_eq!(packet[4], 2); // Check it's actually LoginPassword for now
    packet[4] = 0;

    let res = Wrapper::new_incoming_connection(
            peer2_pk, peer2_sk, Credentials::None, peer2_allowed_credentials, packet);
    assert!(res.is_err());
    assert_eq!(AuthFailure::AuthNone, res.err().unwrap());
}

#[test]
fn loginpassword_noreciprocal_noupkeep_piggyback() {
    init();

    let peer1_credentials = Credentials::LoginPassword {
        login: arr_to_vec(b"login"),
        password: arr_to_vec(b"pass"),
    };
    let mut peer2_allowed_credentials = HashMap::new();
    peer2_allowed_credentials.insert(peer1_credentials.clone(), "peer1");

    let (peer1_pk, peer1_sk) = gen_keypair();
    let (peer2_pk, peer2_sk) = gen_keypair();

    let mut peer1 = Wrapper::new_outgoing_connection(
            peer1_pk, peer1_sk, peer2_pk, peer1_credentials, None, ());

    assert_eq!(peer1.connection_state(), ConnectionState::Uninitialized);

    // Hello from 1 to 2.

    let mut packets = peer1.wrap_message_immediately(&arr_to_vec(b"piggyback (1)"));
    assert_eq!(packets.len(), 1);
    let packet = packets.remove(0);

    let (mut peer2, messages) = Wrapper::new_incoming_connection(
            peer2_pk, peer2_sk, Credentials::None, peer2_allowed_credentials, packet).unwrap();
    assert_eq!(messages, arr_to_vec(b"piggyback (1)"));
    assert_eq!(peer1.connection_state(), ConnectionState::Handshake);
    assert_eq!(peer2.connection_state(), ConnectionState::Handshake);

    // Key from 2 to 1.

    let mut packets = peer2.wrap_message_immediately(&arr_to_vec(b"piggyback (2)"));
    assert_eq!(packets.len(), 1);
    let packet = packets.remove(0);

    let messages = peer1.unwrap_message(packet).unwrap();

    assert_eq!(messages, vec![arr_to_vec(b"piggyback (2)")]);
    assert_eq!(peer1.connection_state(), ConnectionState::Established);
    assert_eq!(peer2.connection_state(), ConnectionState::Handshake);
}
