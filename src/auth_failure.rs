
/// Enumeration used for reporting errors in authenticating
/// a handshake or a data packet.
#[derive(Debug)]
#[derive(Clone)]
pub enum AuthFailure {
    /// An incoming peer tried an auth method that is not None/Password/LoginPassword
    UnknownAuthMethod(u8),
    /// An incoming peer tried to connect with None auth.
    AuthNone,
    /// An incoming peer tried to connect with credentials unknown to us.
    InvalidCredentials,
    /// A peer used a public key different than expected.
    WrongPublicKey,
    /// The packet type does not match the session state.
    UnexpectedPacket,
    /// The packet was too short to be decrypted (handshake of size < 120,
    /// or data of size < 48)
    PacketTooShort,
    /// The packet had a bad format or its auth code was invalid.
    CorruptedPacket,
    /// The packet's nonce is way lower than the max packet nonce
    /// (ie. difference > 64) seen so far.
    LatePacket,
    /// This packet was already received (detected using the nonce as a packet id)
    Replay,
    /// The nonce is cannot be stored in an u64. This is not supported
    /// by this implementation.
    NonceTooBig,
}
