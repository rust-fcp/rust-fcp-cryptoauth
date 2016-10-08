extern crate fcp_cryptoauth;

use std::net::{UdpSocket, SocketAddr, IpAddr, Ipv6Addr};

use fcp_cryptoauth::authentication::AuthChallenge;
use fcp_cryptoauth::session::Session;
use fcp_cryptoauth::keys::{gen_keypair, PublicKey};
use fcp_cryptoauth::hello::create_hello;

pub fn main() {
    let (my_pk, my_sk) = gen_keypair();
    let their_pk = PublicKey::new_from_base32(b"2j1xz5k5y1xwz7kcczc4565jurhp8bbz1lqfu9kljw36p3nmb050.k").unwrap();
    // Corresponding secret key: 824736a667d85582747fde7184201b17d0e655a7a3d9e0e3e617e7ca33270da8
    let mut session = Session::new(my_pk, my_sk, their_pk);

    let login = "foo".to_owned().into_bytes();
    let password = "bar".to_owned().into_bytes();
    let challenge = AuthChallenge::LoginPassword { login: login, password: password };
    let hello = create_hello(&mut session, challenge);
    let bytes = hello.raw;

    println!("{:?}", bytes);
    let sock = UdpSocket::bind("[::1]:12345").unwrap();
    let dest = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 54321);
    sock.send_to(&bytes, dest).unwrap();
}
