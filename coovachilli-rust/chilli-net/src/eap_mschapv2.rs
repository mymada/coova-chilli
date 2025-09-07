use crate::eap::{EapPacket, EapCode, EapType};
use crate::mschapv2;

#[derive(Debug)]
pub enum State {
    Start,
    ChallengeSent {
        server_challenge: [u8; mschapv2::CHALLENGE_LENGTH],
        identifier: u8,
    },
    Success,
    Failure,
}

#[derive(Debug)]
pub struct EapMschapV2Machine {
    pub state: State,
}

impl EapMschapV2Machine {
    pub fn new() -> Self {
        EapMschapV2Machine {
            state: State::Start,
        }
    }

    pub fn start(&mut self, start_packet: &EapPacket) -> Option<Vec<u8>> {
        let server_challenge = mschapv2::generate_challenge();
        let identifier = start_packet.identifier.wrapping_add(1);
        self.state = State::ChallengeSent { server_challenge, identifier };

        let mut mschapv2_data = Vec::new();
        mschapv2_data.push(0x01); // Op-Code: Challenge
        mschapv2_data.push(identifier);
        let mschapv2_length = (4 + 1 + 16) as u16;
        mschapv2_data.extend_from_slice(&mschapv2_length.to_be_bytes());
        mschapv2_data.push(16); // Value-Size
        mschapv2_data.extend_from_slice(&server_challenge);

        let mut eap_data = vec![EapType::MsChapV2 as u8];
        eap_data.extend_from_slice(&mschapv2_data);

        let response_packet = EapPacket {
            code: EapCode::Request,
            identifier,
            data: &eap_data,
        };
        Some(response_packet.to_bytes())
    }

    pub fn step(&mut self, eap_payload: &[u8], password: &str) -> Option<Vec<u8>> {
        let state = std::mem::replace(&mut self.state, State::Failure);
        match state {
            State::ChallengeSent { server_challenge, identifier } => {
                if eap_payload.is_empty() || eap_payload[0] != EapType::MsChapV2 as u8 {
                    return None;
                }
                let mschapv2_payload = &eap_payload[1..];
                if mschapv2_payload.is_empty() || mschapv2_payload[0] != 0x02 { // Op-Code: Response
                    self.state = State::Failure;
                    return None;
                }

                let (peer_challenge, nt_response, username) = match parse_response(mschapv2_payload) {
                    Some(val) => val,
                    None => {
                        self.state = State::Failure;
                        return None;
                    }
                };

                if mschapv2::verify_response(&server_challenge, &peer_challenge, &username, &nt_response, password) {
                    let success_response = mschapv2::generate_success_response(password, &nt_response);
                    self.state = State::Success;
                    let mut data = vec![EapType::MsChapV2 as u8, 0x03]; // Op-Code: Success
                    data.extend_from_slice(&success_response);
                    let response_packet = EapPacket {
                        code: EapCode::Request,
                        identifier: identifier.wrapping_add(1),
                        data: &data,
                    };
                    Some(response_packet.to_bytes())
                } else {
                    self.state = State::Failure;
                    None
                }
            }
            _ => {
                self.state = State::Failure;
                None
            }
        }
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.state, State::Success | State::Failure)
    }
}

fn parse_response(payload: &[u8]) -> Option<([u8; 16], [u8; 24], String)> {
    if payload.len() < 4 { return None; }
    let _identifier = payload[1];
    let length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if payload.len() < length { return None; }
    if length < 53 { return None; }

    let peer_challenge: [u8; 16] = payload[4..20].try_into().ok()?;
    let nt_response: [u8; 24] = payload[28..52].try_into().ok()?;
    let name = String::from_utf8(payload[53..length].to_vec()).ok()?;

    Some((peer_challenge, nt_response, name))
}
