extern crate hex;
extern crate byteorder;
extern crate rust_sodium;

pub mod auth_failure;
pub mod cryptography;
pub mod passwords;
pub mod keys;
pub mod handshake_packet;
pub mod session;
pub mod authentication;
pub mod handshake;
pub mod connection;

pub mod wrapper;

/// Initializes fcp_cryptoauth. Must be called before any
/// feature is used.
///
/// Actually, its only purpose is to initialize the cryptographic
/// library.
pub fn init() {
    rust_sodium::init();
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
