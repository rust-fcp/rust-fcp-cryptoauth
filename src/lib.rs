extern crate hex;
extern crate rust_sodium;

pub mod keys;
pub mod packet;
pub mod session;
pub mod authentication;
pub mod hello;

pub fn init() {
    rust_sodium::init();
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
