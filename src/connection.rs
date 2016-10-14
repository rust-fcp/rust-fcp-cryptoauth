//! Handling of the connection once the handshake was made.

use byteorder::{ByteOrder, BigEndian};

use cryptography::crypto_box;
use auth_failure::AuthFailure;

/// Implementation of the replay protector, as defined by
/// https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#replayprotector
/// with 64 bits instead of 32.
fn check_packet_nonce(their_nonce_offset: &mut u32, their_nonce_bitfield: &mut u64, packet_nonce: &[u8; 4]) -> Result<(), AuthFailure> {
    let packet_nonce = BigEndian::read_u32(packet_nonce);
    if packet_nonce < *their_nonce_offset {
        return Err(AuthFailure::LatePacket)
    }
    let ahead: u32 = packet_nonce - *their_nonce_offset;
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
        their_nonce_offset: &mut u32,
        their_nonce_bitfield: &mut u64,
        shared_secret_key: &crypto_box::PrecomputedKey,
        packet: &[u8],
        ) -> Result<Vec<u8>, AuthFailure>{

    let mut nonce = [0u8; crypto_box::NONCEBYTES];
    nonce[crypto_box::NONCEBYTES-4..].copy_from_slice(&packet[0..4]);
    let nonce = crypto_box::Nonce::from_slice(&nonce).unwrap();

    let mut packet_nonce = [0u8; 4];
    packet_nonce.copy_from_slice(&packet[0..4]);
    let packet_end = &packet[4..];

    use hex::ToHex;
    match crypto_box::open_precomputed(packet_end, &nonce, shared_secret_key) {
        Err(e) => {
            Err(AuthFailure::CorruptedPacket)
        },
        Ok(msg) => {
            try!(check_packet_nonce(their_nonce_offset, their_nonce_bitfield, &packet_nonce));
            Ok(msg)
        },
    }
}

pub fn seal_message(
        my_last_nonce: &mut u32,
        shared_secret_key: &crypto_box::PrecomputedKey,
        message: &[u8],
        ) -> Vec<u8> {
    *my_last_nonce += 1;
    let mut buf = vec![0u8; crypto_box::NONCEBYTES];
    BigEndian::write_u32(&mut buf[crypto_box::NONCEBYTES-4..], *my_last_nonce);
    let nonce = crypto_box::Nonce::from_slice(&buf).unwrap();

    let mut packet = vec![0u8; 4];
    BigEndian::write_u32(&mut packet, *my_last_nonce);
    use hex::ToHex;
    packet.extend(crypto_box::seal_precomputed(message, &nonce, shared_secret_key));
    packet
}
