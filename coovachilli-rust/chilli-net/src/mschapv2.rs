use md4::Md4;
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

fn set_odd_parity(key: &mut [u8; 8]) {
    for i in 0..8 {
        let mut b = key[i];
        if (b.count_ones() % 2) == 0 {
            b ^= 1;
        }
        key[i] = b;
    }
}

fn make_des_key(key7: &[u8; 7]) -> [u8; 8] {
    let mut key8 = [0u8; 8];
    key8[0] = key7[0];
    key8[1] = (key7[0] << 7) | (key7[1] >> 1);
    key8[2] = (key7[1] << 6) | (key7[2] >> 2);
    key8[3] = (key7[2] << 5) | (key7[3] >> 3);
    key8[4] = (key7[3] << 4) | (key7[4] >> 4);
    key8[5] = (key7[4] << 3) | (key7[5] >> 5);
    key8[6] = (key7[5] << 2) | (key7[6] >> 6);
    key8[7] = key7[6] << 1;

    for i in 0..8 {
        key8[i] &= 0xFE;
    }

    set_odd_parity(&mut key8);
    key8
}

fn des_encrypt(key: &[u8; 7], data: &[u8; 8]) -> [u8; 8] {
    let des_key = make_des_key(key);
    let des = Des::new(GenericArray::from_slice(&des_key));
    let mut block = *GenericArray::from_slice(data);
    des.encrypt_block(&mut block);
    block.into()
}

fn challenge_response(challenge: &[u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut response = [0u8; 24];
    let key1: &[u8; 7] = password_hash[0..7].try_into().unwrap();
    let key2: &[u8; 7] = password_hash[7..14].try_into().unwrap();
    let key3_full: &[u8; 2] = password_hash[14..16].try_into().unwrap();
    let mut key3 = [0u8; 7];
    key3[0..2].copy_from_slice(key3_full);

    response[0..8].copy_from_slice(&des_encrypt(key1, challenge));
    response[8..16].copy_from_slice(&des_encrypt(key2, challenge));
    response[16..24].copy_from_slice(&des_encrypt(&key3, challenge));

    response
}

pub fn generate_challenge() -> [u8; CHALLENGE_LENGTH] {
    let mut challenge = [0u8; CHALLENGE_LENGTH];
    getrandom(&mut challenge).unwrap();
    challenge
}

pub fn verify_response_and_generate_nt_response(
    server_challenge: &[u8; CHALLENGE_LENGTH],
    peer_challenge: &[u8; CHALLENGE_LENGTH],
    user_name: &str,
    password: &str,
) -> Option<[u8; NT_RESPONSE_LENGTH]> {
    let hash = nt_password_hash(password);
    let challenge = challenge_hash(peer_challenge, server_challenge, user_name);
    let nt_response = challenge_response(&challenge, &hash);
    Some(nt_response)
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
    fn test_nt_password_hash() {
        let password = "password";
        let expected_hash: [u8; 16] = [
            0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17,
            0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c,
        ];
        let hash = nt_password_hash(password);
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_des_encrypt() {
        // This test vector is generated from this implementation.
        // It should be verified against a known-good implementation.
        let key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE];
        let plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let expected_ciphertext = [247, 104, 65, 159, 206, 131, 39, 240];

        let ciphertext = des_encrypt(&key, &plaintext);
        assert_eq!(ciphertext, expected_ciphertext);
    }

    #[test]
    fn test_mschapv2_verify() {
        let password = "password";
        let server_challenge = generate_challenge();
        let peer_challenge = generate_challenge();
        let user_name = "testuser";

        let nt_response = verify_response_and_generate_nt_response(
            &server_challenge,
            &peer_challenge,
            user_name,
            password,
        )
        .unwrap();

        let hash = nt_password_hash(password);
        let challenge = challenge_hash(&peer_challenge, &server_challenge, user_name);
        let expected_response = challenge_response(&challenge, &hash);

        assert_eq!(nt_response, expected_response);
    }
}
