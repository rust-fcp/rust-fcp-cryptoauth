extern crate rust_sodium;

pub mod packet;

pub fn init() {
    rust_sodium::init();
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
