use md4::{Md4, Digest};
use des::Des;
use des::cipher::{KeyInit, BlockEncrypt};
use getrandom::getrandom;
use sha1::{Sha1, Digest as _};
use des::cipher::generic_array::GenericArray;

pub const CHALLENGE_LENGTH: usize = 16;
pub const NT_RESPONSE_LENGTH: usize = 24;
pub const AUTH_RESPONSE_LENGTH: usize = 42; // "S=" + 40 hex chars

fn nt_password_hash(password: &str) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>());
    hasher.finalize().into()
}

fn challenge_hash(peer_challenge: &[u8], server_challenge: &[u8], user_name: &str) -> [u8; 8] {
    let mut hasher = Sha1::new();
    hasher.update(peer_challenge);
    hasher.update(server_challenge);
    hasher.update(user_name.as_bytes());
    let hash = hasher.finalize();
    hash[..8].try_into().unwrap()
}

fn des_encrypt(key: &[u8; 7], data: &[u8; 8]) -> [u8; 8] {
    let mut key_with_parity = [0u8; 8];
    key_with_parity[0] = key[0];
    key_with_parity[1] = ((key[0] << 7) & 0x80) | (key[1] >> 1);
    key_with_parity[2] = ((key[1] << 6) & 0xC0) | (key[2] >> 2);
    key_with_parity[3] = ((key[2] << 5) & 0xE0) | (key[3] >> 3);
    key_with_parity[4] = ((key[3] << 4) & 0xF0) | (key[4] >> 4);
    key_with_parity[5] = ((key[4] << 3) & 0xF8) | (key[5] >> 5);
    key_with_parity[6] = ((key[5] << 2) & 0xFC) | (key[6] >> 6);
    key_with_parity[7] = (key[6] << 1) & 0xFE;

    for i in 0..8 {
        if (key_with_parity[i].count_ones() % 2) == 0 {
            key_with_parity[i] |= 1;
        }
    }

    let des = Des::new(GenericArray::from_slice(&key_with_parity));
    let mut block = *GenericArray::from_slice(data);
    des.encrypt_block(&mut block);
    block.into()
}

fn challenge_response(challenge: &[u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut response = [0u8; 24];
    let key1: &[u8; 7] = password_hash[0..7].try_into().unwrap();
    let key2: &[u8; 7] = password_hash[7..14].try_into().unwrap();
    let key3: &[u8; 2] = password_hash[14..16].try_into().unwrap();
    let mut key3_7b = [0u8; 7];
    key3_7b[0..2].copy_from_slice(key3);


    response[0..8].copy_from_slice(&des_encrypt(key1, challenge));
    response[8..16].copy_from_slice(&des_encrypt(key2, challenge));
    response[16..24].copy_from_slice(&des_encrypt(&key3_7b, challenge));

    response
}

pub fn generate_challenge() -> [u8; CHALLENGE_LENGTH] {
    let mut challenge = [0u8; CHALLENGE_LENGTH];
    getrandom(&mut challenge).unwrap();
    challenge
}

pub fn verify_response(
    server_challenge: &[u8; CHALLENGE_LENGTH],
    peer_challenge: &[u8; CHALLENGE_LENGTH],
    user_name: &str,
    nt_response: &[u8; NT_RESPONSE_LENGTH],
    password: &str,
) -> bool {
    let hash = nt_password_hash(password);
    let challenge = challenge_hash(peer_challenge, server_challenge, user_name);
    let expected_response = challenge_response(&challenge, &hash);
    expected_response == *nt_response
}

pub fn generate_success_response(
    password: &str,
    nt_response: &[u8; NT_RESPONSE_LENGTH],
) -> [u8; AUTH_RESPONSE_LENGTH] {
    let hash = nt_password_hash(password);
    let mut magic = [0u8; 39];
    magic.copy_from_slice(b"Magic server to client signing constant");
    let mut sha1 = Sha1::new();
    sha1.update(&hash);
    sha1.update(nt_response);
    sha1.update(&magic);
    let digest = sha1.finalize();

    let mut magic2 = [0u8; 40];
    magic2.copy_from_slice(b"Pad to make it do more than one iteration");
    let mut sha2 = Sha1::new();
    sha2.update(&digest);
    sha2.update(&magic2);

    let mut response = [0u8; AUTH_RESPONSE_LENGTH];
    response[0..2].copy_from_slice(b"S=");
    hex::encode_to_slice(&sha2.finalize(), &mut response[2..]).unwrap();
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mschapv2_verify() {
        let password = "password";
        let server_challenge = generate_challenge();
        let peer_challenge = generate_challenge();
        let user_name = "testuser";

        let nt_hash = nt_password_hash(password);
        let challenge = challenge_hash(&peer_challenge, &server_challenge, user_name);
        let nt_response = challenge_response(&challenge, &nt_hash);

        assert!(verify_response(
            &server_challenge,
            &peer_challenge,
            user_name,
            &nt_response,
            password
        ));

        let mut wrong_nt_response = nt_response;
        wrong_nt_response[0] ^= 0xff;
        assert!(!verify_response(
            &server_challenge,
            &peer_challenge,
            user_name,
            &wrong_nt_response,
            password
        ));
    }
}
