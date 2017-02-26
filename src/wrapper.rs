//! Main wrapper function for CryptoAuth connections.
//! For normal usage of CryptoAuth, everything you need should be
//! in this module (or reexported by it).
//!
//! This module's public interface is also less likely to change
//! in future versions of CryptoAuth.
//!
//! If you do not need access to CryptoAuth packets or change the
//! authentication logic, and you ever see something you need is not
//! available in this module (or reexported by it), please report it.

use std::collections::HashMap;
use byteorder::{ByteOrder, BigEndian};

use passwords::PasswordStore;
use session::{Session, SessionState};
use handshake;
use handshake_packet::{HandshakePacket, HandshakePacketType};
use connection;

pub use cryptography::crypto_box::{PublicKey, SecretKey, gen_keypair};
pub use keys::{FromBase32, FromHex, publickey_to_ipv6addr};
pub use auth_failure::AuthFailure;
pub use authentication::Credentials;
pub use super::init;

fn hashmap_to_password_store<PeerId: Clone>(mut map: HashMap<Credentials, PeerId>,) -> PasswordStore<PeerId> {
    let mut store = PasswordStore::new();
    for (credentials, peer_id) in map.drain() {
        match credentials {
            Credentials::LoginPassword { login, password } => store.add_peer(Some(&login), password, peer_id),
            Credentials::Password { password } => store.add_peer(None, password, peer_id),
            Credentials::None => unimplemented!(),
        }
    }
    store
}

/// Used to report the state of the connection at a given time.
#[derive(Eq)]
#[derive(PartialEq)]
#[derive(Clone)]
#[derive(Debug)]
pub enum ConnectionState {
    /// No packet has been sent or received yet.
    Uninitialized,
    /// We are in the handshake phase. `wrap_message` will drop messages.
    Handshake,
    /// We are in the normal phase.
    Established,
}

/// Main wrapper class around a connection.
/// Provides methods to encrypt and decrypt messages.
///
/// This structure does not store arbitrary-sized messages from the
/// network, only arrays whose size is statically known.
/// This means that it cannot be used by network attackers to
/// make it use all the memory on the system.
pub struct Wrapper<PeerId: Clone> {
    my_credentials: Credentials,
    password_store: Option<PasswordStore<PeerId>>,
    peer_id: Option<PeerId>,
    my_session_handle: Option<u32>,
    peer_session_handle: Option<u32>,
    session: Session,
}

impl<PeerId: Clone> Wrapper<PeerId> {
    /// Creates a new `Wrapper` for a connection initiated by us.
    ///
    /// `my_credentials` is the login/password used to authenticate
    /// to the other peer.
    ///
    /// `allowed_peers` has the same function as for
    /// `new_incoming_connection` and may be used if the other peer resets
    /// the connection.
    /// If set to None, no authentication will be required for incoming
    /// peers.
    ///
    /// `peer_id` is an arbitrary value opaque to `fcp_cryptoauth`,
    /// used by the calling library to identify the peer.
    /// It does not have to be unique (even `()` works).
    /// It won't be sent over the network by `fcp_cryptoauth`.
    ///
    /// `session_handle`, if provided, is an integer that will be sent in
    /// the CA handshake packets to ask the peer to use is as a *prefix*
    /// to future CA packets.
    /// If provided, a `session_handle` will also be expected from the other
    /// peer, and available as `peer_session_handle`.
    /// In the FCP, this is used for all inner (end-to-end) CA sessions,
    /// and never for outer (point-to-point) sessions.
    pub fn new_outgoing_connection(
            my_pk: PublicKey, my_sk: SecretKey,
            their_pk: PublicKey,
            my_credentials: Credentials,
            allowed_peers: Option<HashMap<Credentials, PeerId>>,
            peer_id: PeerId,
            session_handle: Option<u32>,
            ) -> Wrapper<PeerId> {

        let password_store = allowed_peers.map(hashmap_to_password_store);

        Wrapper {
            my_credentials: my_credentials,
            password_store: password_store,
            peer_id: Some(peer_id),
            my_session_handle: session_handle,
            peer_session_handle: None,
            session: Session::new(my_pk, my_sk, their_pk, SessionState::UninitializedKnownPeer),
        }
    }

    fn parse_hello(session: &mut Session, password_store: &Option<PasswordStore<PeerId>>, packet: &HandshakePacket) -> Result<(Option<PeerId>, Vec<u8>), AuthFailure> {
        match *password_store {
            Some(ref password_store) => {
                 let (peer_id, data) = try!(handshake::parse_hello_packet(session, password_store, &packet));
                 Ok((Some(peer_id.clone()), data))
            },
            None => Ok((None, try!(handshake::parse_authnone_hello_packet(session, &packet)))),
        }
    }


    /// Creates a new `Wrapper` for a connection initiated by the peer.
    ///
    /// `my_credentials` is the login/password used to authenticate
    /// back to the peer, if we have to reset the connection.
    ///
    /// `allowed_peers` is a set of credentials the peer is allowed
    /// to use to identicate.
    /// Once a peer used one of these credentials, the associated value
    /// is used as its peer id so we know who this is.
    /// If set to None, no authentication will be required for incoming
    /// peers.
    ///
    /// `session_handle` is the same as for `new_outgoing_connection`.
    ///
    /// Returns `Err` if and only if the message is not a well-formed
    /// Hello packet or the peer is not in the `allowed_peers`.
    /// Otherwise, returns `Ok((wrapper, piggybacked_message))`.
    pub fn new_incoming_connection(
            my_pk: PublicKey, my_sk: SecretKey,
            my_credentials: Credentials,
            allowed_peers: Option<HashMap<Credentials, PeerId>>,
            session_handle: Option<u32>,
            packet: Vec<u8>,
            ) -> Result<(Wrapper<PeerId>, Vec<u8>), AuthFailure> {

        let packet = HandshakePacket { raw: packet };

        match packet.packet_type() {
            Ok(HandshakePacketType::Hello) | Ok(HandshakePacketType::RepeatHello) => (),
            _ => return Err(AuthFailure::UnexpectedPacket(format!("Incoming connection started with a non-Hello packet ({:?}).", packet.packet_type()))),
        }

        let password_store = allowed_peers.map(hashmap_to_password_store);
        let their_pk = match handshake::pre_parse_hello_packet(&packet) {
            Some(their_pk) => their_pk,
            None => panic!("pre_parse_hello_packet should not return None on Hello packets.'"),
        };
        let mut session = Session::new(
                my_pk, my_sk, their_pk, SessionState::UninitializedUnknownPeer);

        let (peer_id, content) = try!(Wrapper::parse_hello(&mut session, &password_store, &packet));

        let mut wrapper = Wrapper {
            my_credentials: my_credentials,
            password_store: password_store,
            peer_id: peer_id,
            my_session_handle: session_handle,
            peer_session_handle: None,
            session: session,
        };
        let (handle, new_content) = wrapper.extract_session_handle(content);
        wrapper.peer_session_handle = handle;
        Ok((wrapper, new_content))
    }

    /// Takes an unencrypted message and returns one (eventually more
    /// or zero) encrypted packet containing this message
    /// (eventually CryptoAuth-specific packets).
    ///
    /// Returns packets that should be sent.
    ///
    /// The encryption used by this method is guaranteed to be
    /// forward secret; if forward secrecy is not yet available for
    /// the current connection, messages will be dropped until it is.
    ///
    /// If you need neither forward secrecy or protection against the data
    /// being replayed and want to send a message as fast as possible,
    /// use `wrap_message_immediately`
    /// (for now, the only difference is for the calls to
    /// to `wrap_message` / `wrap_message_immediately` made before
    /// the handshake is finished).
    pub fn wrap_message(&mut self, msg: &[u8]) -> Vec<Vec<u8>> {
        let mut packets = self.upkeep();
        match self.session.state {
            SessionState::Established { ref shared_secret_key, ref initiator_is_me, .. } => {
                packets.push(connection::seal_message(
                        &mut self.session.my_last_nonce, shared_secret_key, *initiator_is_me, msg))

            }
            _ => {} // forward-secrecy not yet available.
        };
        if self.session.my_last_nonce >= 0xfffffff0 {
            // Little nonce space left
            self.session.reset();
            packets.append(&mut self.upkeep());
        }
        packets
    }

    fn prefix_session_handle(&self, msg: &[u8]) -> Vec<u8> {
        match self.my_session_handle {
            None => msg.to_vec(), // TODO: do not copy
            Some(handle) => {
                let mut final_msg = vec![0; msg.len()+4];
                BigEndian::write_u32(&mut final_msg[0..4], handle);
                final_msg[4..].copy_from_slice(msg); // TODO: do not copy
                final_msg
            },
        }
    }

    /// Similar to `wrap_message`, but tries to send the message
    /// faster, but does not guarantee forward secrecy
    /// of the message, and the content may be replayed by anyone.
    ///
    /// For now, the behavior of `wrap_message` and
    /// `wrap_message_immediately` only differs on the first wrapped
    /// message: a wrapped message is not forward secret if and only if
    /// it is passed to the first call of `wrap_message_immediately`
    /// of the session and `wrap_message` has never been called before.
    pub fn wrap_message_immediately(&mut self, msg: &[u8]) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        match self.session.state {
            SessionState::UninitializedUnknownPeer => {
                panic!("A Wrapper's Session state should never be UninitializedUnknownPeer.")
            },
            SessionState::UninitializedKnownPeer |
            SessionState::SentHello { .. } |
            SessionState::ReceivedHello { .. } |
            SessionState::WaitingKey { .. } |
            SessionState::SentKey { .. } => {
                let final_msg = self.prefix_session_handle(msg);
                if let Some(packet) = handshake::create_next_handshake_packet(&mut self.session, &self.my_credentials, &final_msg) {
                    packets.push(packet.raw);
                }
            },
            SessionState::Established { ref shared_secret_key, ref initiator_is_me, .. } => {
                packets.push(connection::seal_message(
                        &mut self.session.my_last_nonce, &shared_secret_key, *initiator_is_me, msg))

            },
        };
        if self.session.my_last_nonce >= 0xfffffff0 {
            // Little nonce space left
            self.session.reset();
            packets.append(&mut self.upkeep());
        }
        packets
    }

    fn extract_session_handle(&self, content: Vec<u8>) -> (Option<u32>, Vec<u8>) {
        match self.my_session_handle {
            Some(_) => {
                // It is an inner CA session, we have to extract the
                // session handle
                let handle = Some(BigEndian::read_u32(&content[0..4]));
                let new_content = content[4..].to_vec(); // TODO: do not copy
                (handle, new_content)
            }
            None => (None, content)
        }
    }

    /// Takes an encrypted packet and returns one (eventually more or
    /// zero) decrypted message, which should be considered as incoming
    /// messages.
    ///
    /// A decrypted message can be trusted as coming from the
    /// associated peer (packets which cannot be authenticated are not
    /// decrypted).
    ///
    /// The argument must be a full CryptoAuth packet. On UDP, this
    /// means that the argument must be the *full* content of *one*
    /// UDP datagram.
    ///
    /// For now, there is no case where this returns more than
    /// one message.
    ///
    /// Errors (authentication failures) may be unwrapped without
    /// further action safely. However, it would be a good style to log
    /// them in your application's DEBUG logs.
    pub fn unwrap_message(&mut self, packet: Vec<u8>) -> Result<Vec<Vec<u8>>, AuthFailure> {
        let (packet, packet_type) = if packet.len() < 120 {
            // Cannot be a handshake packet
            // This case disjunction is useless in theory, but it
            // avoids having a temporary HandshakePacket object
            // that is broken (eg. panics if printed)
            (packet, Err(0))
        }
        else {
            // May be a handshake packet
            let handshake_packet = HandshakePacket { raw: packet };
            let packet_type = handshake_packet.packet_type();
            let packet = handshake_packet.raw;
            (packet, packet_type)
        };
        match packet_type {
            Err(packet_first_four_bytes) => {
                // Not a handshake packet
                handshake::finalize(&mut self.session);
                match self.session.state {
                    SessionState::UninitializedUnknownPeer |
                    SessionState::UninitializedKnownPeer |
                    SessionState::SentHello { .. } |
                    SessionState::WaitingKey { .. } |
                    SessionState::ReceivedHello { .. } => {
                        if packet_first_four_bytes == 0 {
                            Err(AuthFailure::PacketTooShort(format!("Size: {}, but I am in state {:?}", packet.len(), self.session.state)))
                        }
                        else {
                            Err(AuthFailure::UnexpectedPacket(format!("Received a non-handshake packet while doing handshake (first four bytes: {:?}u32)", packet_first_four_bytes)))
                        }
                    },
                    SessionState::SentKey { ref shared_secret_key, .. } => {
                        // TODO: factorize with Established
                        let content = try!(connection::open_packet(
                                &mut self.session.their_nonce_offset,
                                &mut self.session.their_nonce_bitfield,
                                &shared_secret_key,
                                false,
                                &packet));
                        let (handle, new_content) = self.extract_session_handle(content);
                        self.peer_session_handle = handle;
                        Ok(vec![new_content])
                    },
                    SessionState::Established { ref shared_secret_key, ref initiator_is_me, .. } => {
                        Ok(vec![try!(connection::open_packet(
                                &mut self.session.their_nonce_offset,
                                &mut self.session.their_nonce_bitfield,
                                &shared_secret_key,
                                *initiator_is_me,
                                &packet))])
                    },
                }
            },
            Ok(HandshakePacketType::Hello) | Ok(HandshakePacketType::RepeatHello) => {
                let (peer_id, content) = try!(Wrapper::parse_hello(
                        &mut self.session, &self.password_store, &HandshakePacket { raw: packet }));
                let (handle, new_content) = self.extract_session_handle(content);
                self.peer_session_handle = handle;
                self.peer_id = peer_id.clone();

                if new_content.len() == 0 {
                    Ok(Vec::new())
                }
                else {
                    Ok(vec![new_content])
                }
            }
            Ok(HandshakePacketType::Key) | Ok(HandshakePacketType::RepeatKey) => {
                match self.session.state.clone() { // TODO: do not clone
                    SessionState::UninitializedUnknownPeer |
                    SessionState::UninitializedKnownPeer |
                    SessionState::ReceivedHello { .. } => {
                        Err(AuthFailure::UnexpectedPacket("Received a key packet while expecting a hello.".to_owned()))
                    },
                    SessionState::SentKey { .. } |
                    SessionState::Established { .. } => {
                        Err(AuthFailure::UnexpectedPacket("Received a key packet while expecting a data packet.".to_owned()))
                    },
                    SessionState::WaitingKey { .. } |
                    SessionState::SentHello { .. } => {
                        let content = try!(handshake::parse_key_packet(
                                &mut self.session, &HandshakePacket { raw: packet }));

                        let (handle, new_content) = self.extract_session_handle(content);
                        self.peer_session_handle = handle;

                        if new_content.len() == 0 {
                            Ok(Vec::new())
                        }
                        else {
                            Ok(vec![new_content])
                        }
                    },
                }
            },
        }
    }

    /// Passes control to the wrapper so it can perform internal
    /// maintainance, eg. repeat packets that have not been responded
    /// to.
    ///
    /// Returns packets that should be sent to the other peer.
    ///
    /// This function should be called from time to time if no message
    /// was wrapped or unwrapped.
    pub fn upkeep(&mut self) -> Vec<Vec<u8>> {
        match self.session.state {
            SessionState::UninitializedUnknownPeer => {
                panic!("A Wrapper's Session state should never be UninitializedUnknownPeer.")
            },
            SessionState::UninitializedKnownPeer |
            SessionState::SentHello { .. } |
            SessionState::WaitingKey { .. } |
            SessionState::ReceivedHello { .. } |
            SessionState::SentKey { .. } => {
                let msg = self.prefix_session_handle(&vec![]);
                if let Some(packet) = handshake::create_next_handshake_packet(&mut self.session, &self.my_credentials, &msg) {
                    vec![packet.raw]
                }
                else {
                    vec![]
                }
            },
            SessionState::Established { .. } => {
                vec![]
            },
        }
    }

    /// Returns the state of the connection.
    pub fn connection_state(&self) -> ConnectionState {
        match self.session.state {
            SessionState::UninitializedUnknownPeer |
            SessionState::UninitializedKnownPeer => {
                ConnectionState::Uninitialized
            },
            SessionState::SentHello { .. } |
            SessionState::WaitingKey { .. } |
            SessionState::ReceivedHello { .. } |
            SessionState::SentKey { .. } => {
                ConnectionState::Handshake
            },
            SessionState::Established { .. } => {
                ConnectionState::Established
            },
        }
    }

    /// Returns the public key of the other peer.
    pub fn their_pk(&self) -> &PublicKey {
        &self.session.their_perm_pk
    }

    /// Returns the peer id of the other peer.
    pub fn peer_id(&self) -> &Option<PeerId> {
        &self.peer_id
    }

    /// Returns the peer id of the other peer.
    pub fn peer_session_handle(&self) -> Option<u32> {
        self.peer_session_handle.clone()
    }
}
