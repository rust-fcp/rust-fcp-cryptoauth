extern crate hex;
extern crate rust_sodium;

pub mod cryptography;
pub mod passwords;
pub mod keys;
pub mod handshake_packet;
pub mod session;
pub mod authentication;
pub mod handshake;

pub fn init() {
    rust_sodium::init();
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
