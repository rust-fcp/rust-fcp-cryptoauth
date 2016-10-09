extern crate hex;
extern crate fcp_cryptoauth;

use std::net::UdpSocket;

use hex::ToHex;

use fcp_cryptoauth::keys::{PublicKey, SecretKey};
use fcp_cryptoauth::hello::parse_hello;
use fcp_cryptoauth::packet::Packet;
use fcp_cryptoauth::passwords::PasswordStore;

pub fn main() {
    let my_sk = SecretKey::new_from_hex(b"ac3e53b518e68449692b0b2f2926ef2fdc1eac5b9dbd10a48114263b8c8ed12e").unwrap();
    let my_pk = PublicKey::new_from_base32(b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k").unwrap();
    let their_pk = PublicKey::new_from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
    // Corresponding secret key: 824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8

    let mut store = PasswordStore::new(my_sk.clone());
    store.add_peer(&"foo".as_bytes().to_vec(), "bar".as_bytes().to_vec(), &their_pk, "my friend");

    let sock = UdpSocket::bind("[::1]:12345").unwrap();

    let mut buf = vec![0u8; 1024];
    let (nb_bytes, _addr) = sock.recv_from(&mut buf).unwrap();
    println!("Received {} bytes", nb_bytes);
    buf.truncate(nb_bytes);
    let packet = Packet { raw: buf };
    println!("{:?}", packet);
    assert_eq!(packet.sender_perm_pub_key(), their_pk.crypto_box_key.0);
    match parse_hello(my_pk, my_sk, &store, &packet) {
        None => println!("Not a hello packet, or hello from unknown peer."),
        Some((_session, peer)) => println!("Hello from: {:?}", peer),
    }
}
