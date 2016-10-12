//! Main wrapper function for CryptoAuth connections.
//! For normal usage of CryptoAuth, everything you need should be
//! in this module.
//!
//! This module's public interface is also less likely to change
//! in future versions of CryptoAuth.
//!
//! If you do not need access to CryptoAuth packets or change the
//! authentication logic, and you ever see something you need is not
//! available in this module, please report it.

use std::collections::HashMap;

use passwords::PasswordStore;
use session::{Session, SessionState};
use handshake;
use handshake_packet::{HandshakePacket, HandshakePacketType};
use authentication::AuthChallenge;
use connection;

pub use cryptography::crypto_box::{PublicKey, SecretKey};
pub use keys::{FromBase32, FromHex};
pub use auth_failure::AuthFailure;

/// Used for specifying authorization credentials of a peer,
/// either oneself or an incoming peer.
#[derive(Eq)]
#[derive(PartialEq)]
#[derive(Hash)]
#[derive(Clone)]
pub struct Credentials {
    pub login: Option<Vec<u8>>,
    pub password: Vec<u8>,
}

impl Credentials {
    fn to_auth_challenge(self) -> AuthChallenge {
        match self.login {
            Some(login) => AuthChallenge::LoginPassword { login: login, password: self.password },
            None => AuthChallenge::Password { password: self.password },
        }
    }
}

fn hashmap_to_password_store<PeerId: Clone>(mut map: HashMap<Credentials, PeerId>,) -> PasswordStore<PeerId> {
    let mut store = PasswordStore::new();
    for (credential, peer_id) in map.drain() {
        match credential.login {
            Some(ref login) => store.add_peer(Some(login), credential.password, peer_id),
            None => store.add_peer(None, credential.password, peer_id),
        }
    }
    store
}

/// Main wrapper class around a connection.
/// Provides methods to encrypt and decrypt messages.
pub struct Wrapper<PeerId: Clone> {
    my_credentials: Credentials,
    password_store: PasswordStore<PeerId>,
    peer_id: PeerId,
    session: Session,
}

impl<PeerId: Clone> Wrapper<PeerId> {
    /// Creates a new `Wrapper` for a connection initiated by us.
    ///
    /// `my_credentials` is the login/password used to authenticate
    /// to the other peer.
    ///
    /// `allowed_peers` has the same function as for
    /// `new_incoming_connection` and will be used if we have to reset
    /// the connection.
    ///
    /// `peer_id` is an arbitrary value used internally to identify
    /// the peer. It won't be sent over the network.
    pub fn new_outgoing_connection(
            my_pk: PublicKey, my_sk: SecretKey,
            their_pk: PublicKey,
            my_credentials: Credentials,
            allowed_peers: Option<HashMap<Credentials, PeerId>>,
            peer_id: PeerId,
            ) -> Wrapper<PeerId> {

        let password_store = match allowed_peers {
            Some(allowed_peers) => hashmap_to_password_store(allowed_peers),
            None => PasswordStore::new(),
        };
        Wrapper {
            my_credentials: my_credentials,
            password_store: password_store,
            peer_id: peer_id,
            session: Session::new(my_pk, my_sk, their_pk, SessionState::UninitializedKnownPeer),
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
    ///
    /// Returns `Err` if and only if the message is not a well-formed
    /// Hello packet or the peer is not in the `allowed_peers`.
    /// Otherwise, returns `Ok((wrapper, piggybacked_message))`.
    pub fn new_incoming_connection(
            my_pk: PublicKey, my_sk: SecretKey,
            my_credentials: Credentials,
            allowed_peers: HashMap<Credentials, PeerId>,
            packet: Vec<u8>,
            ) -> Result<(Wrapper<PeerId>, Vec<u8>), AuthFailure> {

        let packet = HandshakePacket { raw: packet };

        match packet.packet_type() {
            Ok(HandshakePacketType::Hello) | Ok(HandshakePacketType::RepeatHello) => (),
            _ => return Err(AuthFailure::UnexpectedPacket),
        }

        let password_store = hashmap_to_password_store(allowed_peers);
        let their_pk = match handshake::pre_parse_hello_packet(&packet) {
            Some(their_pk) => their_pk,
            None => return Err(AuthFailure::UnexpectedPacket),
        };
        let mut session = Session::new(
                my_pk, my_sk, their_pk, SessionState::UninitializedUnknownPeer);
        let (peer_id, data) = try!(handshake::parse_hello_packet(
                &mut session, &password_store, &packet));
        let peer_id = peer_id.clone();

        let wrapper = Wrapper {
            my_credentials: my_credentials,
            password_store: password_store,
            peer_id: peer_id,
            session: session,
        };
        Ok((wrapper, data))
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
        match self.session.state {
            SessionState::Established { ref shared_secret_key, .. } => {
                vec![connection::seal_message(
                        &mut self.session.my_last_nonce, shared_secret_key, msg)]
            }
            _ => vec![] // forward-secrecy not yet available.
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
        match self.session.state {
            SessionState::UninitializedUnknownPeer => {
                panic!("A Wrapper's Session state should never be UninitializedUnknownPeer.")
            },
            SessionState::UninitializedKnownPeer |
            SessionState::SentHello { .. } |
            SessionState::ReceivedHello { .. } |
            SessionState::SentKey { .. } => {
                let challenge = self.my_credentials.clone().to_auth_challenge();
                vec![handshake::create_next_handshake_packet(&mut self.session, &challenge, msg).raw]
            },
            SessionState::Established { ref shared_secret_key, .. } => {
                vec![connection::seal_message(
                        &mut self.session.my_last_nonce, &shared_secret_key, msg)]
            },
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
        match self.session.state {
            SessionState::UninitializedUnknownPeer => {
                panic!("A Wrapper's Session state should never be UninitializedUnknownPeer.")
            },
            SessionState::UninitializedKnownPeer |
            SessionState::SentHello { .. } |
            SessionState::ReceivedHello { .. } |
            SessionState::SentKey { .. } => {
                let (peer_id, msg) = try!(handshake::parse_handshake_packet(
                        &mut self.session, &self.password_store, &HandshakePacket { raw: packet }));
                let peer_id = peer_id.unwrap(); // Session state is not SentHello, Peer can't be None.
                self.peer_id = peer_id.clone();
                Ok(vec![msg])
            },
            SessionState::Established { ref shared_secret_key, .. } => {
                Ok(vec![try!(connection::open_packet(
                        &mut self.session.their_nonce_offset,
                        &mut self.session.their_nonce_bitfield,
                        &shared_secret_key,
                        &packet))])
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
    pub fn upkeep(&self) -> Vec<Vec<u8>> {
        // TODO: repeat hello / repeat key
        vec![]
    }

    /// Returns the public key of the other peer.
    pub fn their_pk(&self) -> &PublicKey {
        &self.session.their_perm_pk
    }

    /// Returns the peer id of the other peer.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}
