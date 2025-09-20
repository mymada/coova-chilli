//! Represents the state of an EAPOL (802.1x) authentication session.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EapolState {
    Start,
    IdentitySent,
    ChallengeSent,
    Authenticated,
    Failed,
}

impl Default for EapolState {
    fn default() -> Self {
        EapolState::Start
    }
}

#[derive(Debug, Clone)]
pub struct EapolSession {
    /// The client's MAC address.
    pub mac_addr: [u8; 6],
    /// The current state of the EAPOL conversation.
    pub state: EapolState,
    /// The current EAP identifier for this session.
    pub eap_identifier: u8,
    /// The RADIUS `State` attribute, used to correlate messages.
    pub radius_state: Option<Vec<u8>>,
    /// The client's identity (username), once known.
    pub username: Option<String>,
}

impl EapolSession {
    pub fn new(mac_addr: [u8; 6]) -> Self {
        EapolSession {
            mac_addr,
            state: EapolState::Start,
            eap_identifier: 0,
            radius_state: None,
            username: None,
        }
    }
}
