//! Handling of the connection once the handshake was made.

use byteorder::{ByteOrder, BigEndian};

use cryptography::crypto_box;
use auth_failure::AuthFailure;

/// Implementation of the replay protector, as defined by
/// https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#replayprotector
/// with 64 bits instead of 32.
fn check_packet_nonce(their_nonce_offset: &mut u64, their_nonce_bitfield: &mut u64, packet_nonce: &[u8; crypto_box::NONCEBYTES]) -> Result<(), AuthFailure> {
    if packet_nonce[0..crypto_box::NONCEBYTES-8] != [0u8; crypto_box::NONCEBYTES-8] {
        return Err(AuthFailure::NonceTooBig)
    }
    let packet_nonce = BigEndian::read_u64(&packet_nonce[crypto_box::NONCEBYTES-8..crypto_box::NONCEBYTES]);
    if packet_nonce < *their_nonce_offset {
        return Err(AuthFailure::LatePacket)
    }
    let ahead: u64 = packet_nonce - *their_nonce_offset;
    if ahead <= 64 {
        let mask = 1u64 << ahead; // The bit corresponding to this nonce (=packet id) in the bitfield.
        if (mask & *their_nonce_bitfield) == 0 {
            // We have never seen this packet so far.
            *their_nonce_bitfield |= mask; // Remember we got it
        }
        else {
            return Err(AuthFailure::Replay)
        }
    }
    else {
        let slide_window_by = ahead - 64; // Always > 0 in this branch
        *their_nonce_offset += slide_window_by;
        *their_nonce_bitfield <<= slide_window_by;
        *their_nonce_bitfield |= 1;
    }
    Ok(())
}

pub fn open_packet(
        their_nonce_offset: &mut u64,
        their_nonce_bitfield: &mut u64,
        shared_secret_key: &crypto_box::PrecomputedKey,
        packet: &[u8],
        ) -> Result<Vec<u8>, AuthFailure>{

    let mut packet_nonce = [0u8; crypto_box::NONCEBYTES];
    packet_nonce.copy_from_slice(&packet[0..crypto_box::NONCEBYTES]);
    let packet_end = &packet[crypto_box::NONCEBYTES..];
    let nonce = crypto_box::Nonce::from_slice(&packet_nonce).unwrap();

    match crypto_box::open_precomputed(packet_end, &nonce, shared_secret_key) {
        Err(_) => Err(AuthFailure::CorruptedPacket),
        Ok(msg) => {
            try!(check_packet_nonce(their_nonce_offset, their_nonce_bitfield, &packet_nonce));
            Ok(msg)
        },
    }
}

pub fn seal_message(
        my_last_nonce: &mut u64,
        shared_secret_key: &crypto_box::PrecomputedKey,
        message: &[u8],
        ) -> Vec<u8> {
    *my_last_nonce += 1;
    let mut buf = vec![0u8; crypto_box::NONCEBYTES];
    BigEndian::write_u64(&mut buf[crypto_box::NONCEBYTES-8..], *my_last_nonce);
    let nonce = crypto_box::Nonce::from_slice(&buf).unwrap();
    buf.extend(crypto_box::seal_precomputed(message, &nonce, shared_secret_key));
    buf
}
