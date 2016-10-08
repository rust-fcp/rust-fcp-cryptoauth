extern crate hex;
extern crate fcp_cryptoauth;

use std::net::{UdpSocket, SocketAddr, IpAddr, Ipv6Addr};

use hex::ToHex;

use fcp_cryptoauth::authentication::AuthChallenge;
use fcp_cryptoauth::session::Session;
use fcp_cryptoauth::keys::{PublicKey, SecretKey};
use fcp_cryptoauth::hello::create_hello;

pub fn main() {
    let my_sk = SecretKey::new_from_hex(b"ac3e53b518e68449692b0b2f2926ef2fdc1eac5b9dbd10a48114263b8c8ed12e").unwrap();
    let my_pk = PublicKey::new_from_base32(b"2wrpv8p4tjwm532sjxcbqzkp7kdwfwzzbg7g0n5l6g3s8df4kvv0.k").unwrap();
    let their_pk = PublicKey::new_from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
    // Corresponding secret key: 824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8
    let mut session = Session::new(my_pk, my_sk, their_pk);

    let login = "foo".to_owned().into_bytes();
    let password = "bar".to_owned().into_bytes();
    let challenge = AuthChallenge::LoginPassword { login: login, password: password };
    let hello = create_hello(&mut session, challenge);
    println!("0x{}", session.shared_secret.unwrap().to_hex());
    println!("{:?}", hello);
    let bytes = hello.raw;

    let sock = UdpSocket::bind("[::1]:12345").unwrap();
    let dest = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 54321);
    sock.send_to(&bytes, dest).unwrap();
}
