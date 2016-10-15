extern crate fcp_cryptoauth;

use std::collections::HashMap;

use fcp_cryptoauth::wrapper::*;

fn arr_to_vec(s: &[u8]) -> Vec<u8> {
    s.to_owned().to_vec()
}

fn initialize() -> (Wrapper<()>, Wrapper<String>) {
    init();

    let peer1_credentials = Credentials::LoginPassword {
        login: arr_to_vec(b"login"),
        password: arr_to_vec(b"pass"),
    };
    let mut peer2_allowed_credentials = HashMap::new();
    peer2_allowed_credentials.insert(peer1_credentials.clone(), "peer1".to_owned());

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

    (peer1, peer2)
}

#[test]
fn reordered_in_window() {
    let (mut peer1, mut peer2) = initialize();

    let mut packets = peer1.wrap_message(&arr_to_vec(b"msg1"));
    assert_eq!(packets.len(), 1);
    let packet1 = packets.remove(0);

    let mut packets = peer1.wrap_message(&arr_to_vec(b"msg2"));
    assert_eq!(packets.len(), 1);
    let packet2 = packets.remove(0);

    let messages = peer2.unwrap_message(packet2).unwrap();
    assert_eq!(messages, vec![b"msg2"]);

    let messages = peer2.unwrap_message(packet1).unwrap();
    assert_eq!(messages, vec![b"msg1"]);
}

#[test]
fn reordered_in_window_limit() {
    let (mut peer1, mut peer2) = initialize();

    let mut packets = peer1.wrap_message(&arr_to_vec(b"msg1"));
    assert_eq!(packets.len(), 1);
    let packet1 = packets.remove(0);

    for _ in 0..62 {
        peer1.wrap_message(&arr_to_vec(b"filler"));
    }

    let mut packets = peer1.wrap_message(&arr_to_vec(b"msg2"));
    assert_eq!(packets.len(), 1);
    let packet2 = packets.remove(0);

    let messages = peer2.unwrap_message(packet2).unwrap();
    assert_eq!(messages, vec![b"msg2"]);

    let messages = peer2.unwrap_message(packet1).unwrap();
    assert_eq!(messages, vec![b"msg1"]);
}

#[test]
fn reordered_out_window_limit() {
    let (mut peer1, mut peer2) = initialize();

    let mut packets = peer1.wrap_message(&arr_to_vec(b"msg1"));
    assert_eq!(packets.len(), 1);
    let packet1 = packets.remove(0);

    for _ in 0..63 {
        peer1.wrap_message(&arr_to_vec(b"filler"));
    }

    let mut packets = peer1.wrap_message(&arr_to_vec(b"msg2"));
    assert_eq!(packets.len(), 1);
    let packet2 = packets.remove(0);

    let messages = peer2.unwrap_message(packet2).unwrap();
    assert_eq!(messages, vec![b"msg2"]);

    let err = peer2.unwrap_message(packet1).err().unwrap();
    assert_eq!(err, AuthFailure::LatePacket);
}

#[test]
fn ordered_out_window() {
    let (mut peer1, mut peer2) = initialize();

    let mut packets = peer1.wrap_message(&arr_to_vec(b"msg1"));
    assert_eq!(packets.len(), 1);
    let packet1 = packets.remove(0);

    for _ in 0..100 {
        peer1.wrap_message(&arr_to_vec(b"filler"));
    }

    let mut packets = peer1.wrap_message(&arr_to_vec(b"msg2"));
    assert_eq!(packets.len(), 1);
    let packet2 = packets.remove(0);

    let messages = peer2.unwrap_message(packet1).unwrap();
    assert_eq!(messages, vec![b"msg1"]);

    let messages = peer2.unwrap_message(packet2).unwrap();
    assert_eq!(messages, vec![b"msg2"]);
}


#[test]
fn replay() {
    let (mut peer1, mut peer2) = initialize();

    let mut packets = peer1.wrap_message(&arr_to_vec(b"msg1"));
    assert_eq!(packets.len(), 1);
    let packet1 = packets.remove(0);

    for _ in 0..20 {
        peer1.wrap_message(&arr_to_vec(b"filler"));
    }

    let mut packets = peer1.wrap_message(&arr_to_vec(b"msg2"));
    assert_eq!(packets.len(), 1);
    let packet2 = packets.remove(0);

    let messages = peer2.unwrap_message(packet2.clone()).unwrap();
    assert_eq!(messages, vec![b"msg2"]);

    let messages = peer2.unwrap_message(packet1).unwrap();
    assert_eq!(messages, vec![b"msg1"]);

    let err = peer2.unwrap_message(packet2).err().unwrap();
    assert_eq!(err, AuthFailure::Replay);
}
