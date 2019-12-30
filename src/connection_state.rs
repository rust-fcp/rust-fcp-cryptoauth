use session::SessionState;

/// Used to report the state of the connection at a given time.
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum ConnectionState {
    /// No packet has been sent or received yet.
    Uninitialized,
    /// We are in the handshake phase. `wrap_message` will drop messages.
    Handshake,
    /// We are in the normal phase.
    Established,
}

impl<'a> From<&'a SessionState> for ConnectionState {
    fn from(ss: &SessionState) -> ConnectionState {
        match *ss {
            SessionState::UninitializedUnknownPeer | SessionState::UninitializedKnownPeer => {
                ConnectionState::Uninitialized
            }
            SessionState::SentHello { .. }
            | SessionState::WaitingKey { .. }
            | SessionState::ReceivedHello { .. }
            | SessionState::SentKey { .. } => ConnectionState::Handshake,
            SessionState::Established { .. } => ConnectionState::Established,
        }
    }
}
