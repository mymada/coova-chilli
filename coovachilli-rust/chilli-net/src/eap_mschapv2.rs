use crate::eap::{EapPacket, EapCode, EapType};

pub fn create_identity_response(identifier: u8, username: &str) -> EapPacket {
    let mut data = vec![EapType::Identity as u8];
    data.extend_from_slice(username.as_bytes());
    EapPacket {
        code: EapCode::Response,
        identifier,
        data,
    }
}

pub fn parse_challenge_request(packet: &EapPacket) -> Option<([u8; 16], u8)> {
    if packet.code == EapCode::Request && !packet.data.is_empty() && packet.data[0] == EapType::MsChapV2 as u8 {
        let mschapv2_payload = &packet.data[1..];
        if mschapv2_payload.is_empty() || mschapv2_payload[0] != 0x01 { // Op-Code: Challenge
            return None;
        }
        if mschapv2_payload.len() < 18 {
            return None;
        }
        let challenge: [u8; 16] = mschapv2_payload[2..18].try_into().ok()?;
        let identifier = mschapv2_payload[1];
        Some((challenge, identifier))
    } else {
        None
    }
}

pub fn create_challenge_response_packet(
    eap_identifier: u8,
    mschapv2_identifier: u8,
    peer_challenge: &[u8; 16],
    nt_response: &[u8; 24],
    username: &str,
) -> EapPacket {
    let mut data = vec![0x02]; // Op-Code: Response
    data.push(mschapv2_identifier);
    let length = (52 + username.len()) as u16;
    data.extend_from_slice(&length.to_be_bytes());
    data.extend_from_slice(peer_challenge);
    data.extend_from_slice(&[0u8; 8]); // Reserved
    data.extend_from_slice(nt_response);
    data.push(0); // Flags
    data.extend_from_slice(username.as_bytes());

    let eap_data = create_eap_payload(EapType::MsChapV2, &data);
    EapPacket {
        code: EapCode::Response,
        identifier: eap_identifier,
        data: eap_data,
    }
}

pub fn parse_success_request(packet: &EapPacket) -> Option<Vec<u8>> {
    if packet.code == EapCode::Request && !packet.data.is_empty() && packet.data[0] == EapType::MsChapV2 as u8 {
        let mschapv2_payload = &packet.data[1..];
        if mschapv2_payload.is_empty() || mschapv2_payload[0] != 0x03 { // Op-Code: Success
            return None;
        }
        Some(mschapv2_payload[1..].to_vec())
    } else {
        None
    }
}

fn create_eap_payload(eap_type: EapType, data: &[u8]) -> Vec<u8> {
    let mut payload = vec![eap_type as u8];
    payload.extend_from_slice(data);
    payload
}
