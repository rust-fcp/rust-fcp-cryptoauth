extern crate fcp_cryptoauth;
extern crate hex;
extern crate rust_sodium;

use rust_sodium::crypto::box_::curve25519xsalsa20poly1305::{PublicKey, SecretKey};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};

use fcp_cryptoauth::authentication::Credentials;
use fcp_cryptoauth::handshake::{create_next_handshake_packet, parse_handshake_packet};
use fcp_cryptoauth::handshake_packet::{HandshakePacket, HandshakePacketType};
use fcp_cryptoauth::keys::{FromBase32, FromHex};
use fcp_cryptoauth::passwords::PasswordStore;
use fcp_cryptoauth::session::{Session, SessionState};

pub fn main() {
    fcp_cryptoauth::init();

    let my_sk =
        SecretKey::from_hex(b"ac3e53b518e68449692b0b2f2926ef2fdc1eac5b9dbd10a48114263b8c8ed12e")
            .unwrap();
    let my_pk =
        PublicKey::from_base32(b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k").unwrap();
    let their_pk =
        PublicKey::from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
    // Corresponding secret key: 824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8
    let login = "foo".to_owned().into_bytes();
    let password = "bar".to_owned().into_bytes();

    let mut store = PasswordStore::new();
    store.add_peer(Some(&login), password.clone(), "my friend");

    let challenge = Credentials::LoginPassword {
        login: login,
        password: password,
    };
    let initial_state = SessionState::UninitializedKnownPeer;
    let mut session = Session::new(my_pk, my_sk, their_pk, initial_state);

    let sock = UdpSocket::bind("[::1]:12345").unwrap();
    let dest = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 54321);

    println!("Sending hello.");
    let hello = create_next_handshake_packet(&mut session, &challenge, &vec![]);
    let hello = hello.unwrap();
    println!("Session state: {:?}", session.state);
    println!("{:?}", hello);
    assert_eq!(hello.packet_type().unwrap(), HandshakePacketType::Hello);
    let bytes = hello.raw;

    sock.send_to(&bytes, dest).unwrap();

    let mut buf = vec![0u8; 1024];
    let (nb_bytes, addr) = sock.recv_from(&mut buf).unwrap();
    println!("Received {} bytes", nb_bytes);
    buf.truncate(nb_bytes);
    let packet = HandshakePacket { raw: buf };
    println!("{:?}", packet);

    assert_eq!(packet.sender_perm_pub_key(), session.their_perm_pk.0);
    match parse_handshake_packet(&mut session, &store, &packet) {
        Err(e) => println!("Error: {:?}", e),
        Ok((peer, _data)) => println!("{:?} from: {:?}", packet.packet_type(), peer),
    }

    if let SessionState::Established { .. } = session.state {
        println!("Done!")
    } else if let SessionState::ReceivedHello { .. } = session.state {
        // Send Key
        println!("Sending key.");
        let key = create_next_handshake_packet(&mut session, &challenge, &vec![]);
        let key = key.unwrap();
        println!("Session state: {:?}", session.state);
        println!("{:?}", key);
        assert_eq!(key.packet_type().unwrap(), HandshakePacketType::Key);
        let bytes = key.raw;

        sock.send_to(&bytes, dest).unwrap();

        let mut buf = vec![0u8; 1024];
        let (nb_bytes, addr) = sock.recv_from(&mut buf).unwrap();
        println!("Received {} bytes", nb_bytes);
        buf.truncate(nb_bytes);
        let packet = HandshakePacket { raw: buf };
        assert_eq!(packet.packet_type(), Err(4));
        let buf = packet.raw;
    }
}
