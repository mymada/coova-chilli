#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum EapCode {
    Request = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum EapType {
    Identity = 1,
    Notification = 2,
    Nak = 3, // Response only
    Md5Challenge = 4,
    MsChapV2 = 26,
}

#[derive(Debug, Clone)]
pub struct EapPacket {
    pub code: EapCode,
    pub identifier: u8,
    pub data: Vec<u8>,
}

impl EapPacket {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let code_byte = data[0];
        let code = match code_byte {
            1 => EapCode::Request,
            2 => EapCode::Response,
            3 => EapCode::Success,
            4 => EapCode::Failure,
            _ => return None,
        };
        let identifier = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < length {
            return None;
        }
        let packet_data = data[4..length].to_vec();
        Some(EapPacket {
            code,
            identifier,
            data: packet_data,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let length = (4 + self.data.len()) as u16;
        let mut bytes = Vec::with_capacity(length as usize);
        bytes.push(self.code as u8);
        bytes.push(self.identifier);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }
}
