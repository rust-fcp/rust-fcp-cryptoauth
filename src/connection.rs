//! Handling of the connection once the handshake was made.

use byteorder::{BigEndian, ByteOrder, LittleEndian};

use auth_failure::AuthFailure;
use cryptography::crypto_box;

/// Implementation of the replay protector, as defined by
/// https://github.com/cjdelisle/cjdns/blob/cjdns-v17.4/doc/Whitepaper.md#replayprotector
/// with 64 bits instead of 32.
fn check_packet_nonce(
    their_nonce_offset: &mut u32,
    their_nonce_bitfield: &mut u64,
    packet_nonce: &[u8; 4],
) -> Result<(), AuthFailure> {
    let packet_nonce = BigEndian::read_u32(packet_nonce);
    if packet_nonce + 64 <= *their_nonce_offset {
        // Very late packet.
        Err(AuthFailure::LatePacket)
    } else if packet_nonce <= *their_nonce_offset {
        // A bit late packet. Let's make sure we did not already receive it.
        let shift: u32 = *their_nonce_offset - packet_nonce;
        let mask = 1u64 << shift; // The bit corresponding to this nonce (=packet id) in the bitfield.
        if (mask & *their_nonce_bitfield) == 0 {
            // We have never seen this packet so far.
            *their_nonce_bitfield |= mask; // Remember we got it
            Ok(())
        } else {
            return Err(AuthFailure::Replay);
        }
    } else {
        // Packet newer than every other one so far. Slide the window.
        let ahead: u32 = packet_nonce - *their_nonce_offset;
        *their_nonce_offset += ahead;
        assert_eq!(*their_nonce_offset, packet_nonce);
        *their_nonce_bitfield = their_nonce_bitfield.wrapping_shl(ahead);
        *their_nonce_bitfield |= 1;
        Ok(())
    }
}

pub fn open_packet(
    their_nonce_offset: &mut u32,
    their_nonce_bitfield: &mut u64,
    shared_secret_key: &crypto_box::PrecomputedKey,
    initiator_is_me: bool,
    packet: &[u8],
) -> Result<Vec<u8>, AuthFailure> {
    let nonce = BigEndian::read_u32(&packet[0..4]);
    let mut cb_nonce = [0u8; crypto_box::NONCEBYTES];
    {
        // Limit mutable borrowing of cb_nonce
        let slice = if initiator_is_me {
            &mut cb_nonce[0..4]
        } else {
            &mut cb_nonce[4..8]
        };
        LittleEndian::write_u32(slice, nonce);
    }
    let nonce = crypto_box::Nonce::from_slice(&cb_nonce).unwrap();

    let mut packet_nonce = [0u8; 4];
    packet_nonce.copy_from_slice(&packet[0..4]);
    let packet_end = &packet[4..];

    match crypto_box::open_precomputed(packet_end, &nonce, shared_secret_key) {
        Err(()) => Err(AuthFailure::CorruptedPacket(
            "Could not decrypt packet.".to_owned(),
        )),
        Ok(msg) => {
            check_packet_nonce(
                their_nonce_offset,
                their_nonce_bitfield,
                &packet_nonce
            )?;
            Ok(msg)
        }
    }
}

pub fn seal_message(
    my_last_nonce: &mut u32,
    shared_secret_key: &crypto_box::PrecomputedKey,
    initiator_is_me: bool,
    message: &[u8],
) -> Vec<u8> {
    *my_last_nonce += 1;
    let mut buf = vec![0u8; crypto_box::NONCEBYTES];
    {
        // Limit mutable borrowing of buf
        let slice = if initiator_is_me {
            &mut buf[4..8]
        } else {
            &mut buf[0..4]
        };
        LittleEndian::write_u32(slice, *my_last_nonce);
    }
    let nonce = crypto_box::Nonce::from_slice(&buf).unwrap();

    let mut packet = vec![0u8; 4];
    BigEndian::write_u32(&mut packet, *my_last_nonce);
    packet.extend(crypto_box::seal_precomputed(
        message,
        &nonce,
        shared_secret_key,
    ));

    packet
}
