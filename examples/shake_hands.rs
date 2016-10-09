extern crate hex;
extern crate fcp_cryptoauth;

use std::net::{UdpSocket, SocketAddr, IpAddr, Ipv6Addr};

use hex::ToHex;

use fcp_cryptoauth::authentication::AuthChallenge;
use fcp_cryptoauth::session::{Session, SessionState};
use fcp_cryptoauth::keys::{PublicKey, SecretKey};
use fcp_cryptoauth::handshake::{create_next_handshake_packet, parse_handshake_packet};
use fcp_cryptoauth::packet::{Packet, PacketType};
use fcp_cryptoauth::passwords::PasswordStore;

pub fn main() {
    let my_sk = SecretKey::new_from_hex(b"ac3e53b518e68449692b0b2f2926ef2fdc1eac5b9dbd10a48114263b8c8ed12e").unwrap();
    let my_pk = PublicKey::new_from_base32(b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k").unwrap();
    let their_pk = PublicKey::new_from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
    // Corresponding secret key: 824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8
    let mut store = PasswordStore::new(my_sk.clone());
    store.add_peer(&"foo".as_bytes().to_vec(), "bar".as_bytes().to_vec(), &their_pk, "my friend");
    let mut session = Session::new(true, my_pk, my_sk, their_pk);

    let login = "foo".to_owned().into_bytes();
    let password = "bar".to_owned().into_bytes();
    let challenge = AuthChallenge::LoginPassword { login: login, password: password };

    let sock = UdpSocket::bind("[::1]:12345").unwrap();
    let dest = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 54321);

    println!("Sending hello.");
    let hello = create_next_handshake_packet(&mut session, challenge.clone());
    println!("0x{}", session.shared_secret.unwrap().to_hex());
    println!("{:?}", hello);
    assert_eq!(hello.packet_type().unwrap(), PacketType::Hello);
    let bytes = hello.raw;

    sock.send_to(&bytes, dest).unwrap();

    let mut buf = vec![0u8; 1024];
    let (nb_bytes, addr) = sock.recv_from(&mut buf).unwrap();
    println!("Received {} bytes", nb_bytes);
    buf.truncate(nb_bytes);
    let packet = Packet { raw: buf };
    println!("{:?}", packet);

    assert_eq!(packet.sender_perm_pub_key(), session.their_perm_pk.crypto_box_key.0);
    match parse_handshake_packet(&mut session, &store, &packet) {
        None => println!("Not a handshake packet, or handshake from unknown peer."),
        Some(peer) => println!("{:?} from: {:?}", packet.packet_type(), peer),
    }

    if let SessionState::Established(_) = session.state {
        println!("Done!")
    }
    else if session.state == SessionState::ReceivedHello {
        // Send Key
        println!("Sending key.");
        let key = create_next_handshake_packet(&mut session, challenge);
        println!("0x{}", session.shared_secret.unwrap().to_hex());
        println!("{:?}", key);
        assert_eq!(key.packet_type().unwrap(), PacketType::Key);
        let bytes = key.raw;

        sock.send_to(&bytes, dest).unwrap();

        let mut buf = vec![0u8; 1024];
        let (nb_bytes, addr) = sock.recv_from(&mut buf).unwrap();
        println!("Received {} bytes", nb_bytes);
        buf.truncate(nb_bytes);
        let packet = Packet { raw: buf };
        println!("{:?}", packet);
    }
    
}
