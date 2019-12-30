extern crate fcp_cryptoauth;
extern crate hex;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};

use fcp_cryptoauth::*;

use hex::ToHex;

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
    let credentials = Credentials::LoginPassword {
        login: login,
        password: password,
    };
    let mut allowed_peers = HashMap::new();
    allowed_peers.insert(credentials.clone(), "my peer");

    let sock = UdpSocket::bind("[::1]:12345").unwrap();
    let dest = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 54321);

    let mut conn = CAWrapper::new_outgoing_connection(
        my_pk,
        my_sk,
        their_pk,
        credentials,
        Some(allowed_peers),
        "my peer",
        None,
    );

    println!("1");

    for packet in conn.upkeep() {
        sock.send_to(&packet, dest).unwrap();
    }

    let mut buf = vec![0u8; 1024];
    let (nb_bytes, _addr) = sock.recv_from(&mut buf).unwrap();
    assert!(nb_bytes < 1024);
    buf.truncate(nb_bytes);
    println!("Received packet: {}", buf.to_hex());
    for message in conn.unwrap_message(buf).unwrap() {
        println!("Received message: {}", message.to_hex());
    }

    println!("2");

    for packet in conn.upkeep() {
        sock.send_to(&packet, dest).unwrap();
    }

    let mut buf = vec![0u8; 1024];
    let (nb_bytes, _addr) = sock.recv_from(&mut buf).unwrap();
    assert!(nb_bytes < 1024);
    buf.truncate(nb_bytes);
    println!("Received packet: {}", buf.to_hex());
    for message in conn.unwrap_message(buf).unwrap() {
        println!("Received message: {}", message.to_hex());
    }

    println!("3");

    for packet in conn.upkeep() {
        sock.send_to(&packet, dest).unwrap();
    }

    let mut buf = vec![0u8; 1024];
    let (nb_bytes, _addr) = sock.recv_from(&mut buf).unwrap();
    assert!(nb_bytes < 1024);
    buf.truncate(nb_bytes);
    println!("Received packet: {}", buf.to_hex());
    for message in conn.unwrap_message(buf).unwrap() {
        println!("Received message: {}", message.to_hex());
    }

    for i in 4.. {
        println!("{}", i);

        for packet in conn.upkeep() {
            sock.send_to(&packet, dest).unwrap();
        }
        for packet in conn.wrap_message(b"hello!") {
            sock.send_to(&packet, dest).unwrap();
        }

        let mut buf = vec![0u8; 1024];
        let (nb_bytes, _addr) = sock.recv_from(&mut buf).unwrap();
        assert!(nb_bytes < 1024);
        buf.truncate(nb_bytes);
        println!("Received packet: {}", buf.to_hex());
        for message in conn.unwrap_message(buf).unwrap() {
            println!("Received message: {}", message.to_hex());
        }
    }
}
