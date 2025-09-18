// EAPOL Packet Definitions
// Based on IEEE 802.1X

// EAPOL Packet Type
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum EapolType {
    Eap = 0,
    Start = 1,
    Logoff = 2,
    Key = 3,
    EncapsulatedAsfAlert = 4,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct EapolPacket<'a> {
    pub version: u8,
    pub packet_type: EapolType,
    pub length: u16,
    pub payload: &'a [u8],
}

impl<'a> EapolPacket<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let version = data[0];
        let packet_type = match data[1] {
            0 => EapolType::Eap,
            1 => EapolType::Start,
            2 => EapolType::Logoff,
            3 => EapolType::Key,
            4 => EapolType::EncapsulatedAsfAlert,
            _ => return None,
        };
        let length = u16::from_be_bytes([data[2], data[3]]);
        let payload = &data[4..4 + length as usize];

        Some(EapolPacket {
            version,
            packet_type,
            length,
            payload,
        })
    }
}
