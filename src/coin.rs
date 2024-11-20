// NOTE: the coin was used in the DKG, which is no longer required for the Kintsugi protocol
#![allow(dead_code)]

use curve25519_dalek::RistrettoPoint;

use crate::{keypair::Keypair, signature::Signature};

pub struct Coin {}

impl Coin {
    pub fn get_value(
        keypair: Keypair,
        aba_id: i32,
        round_number: usize,
        combined_comm_vec: Vec<RistrettoPoint>,
    ) -> bool {
        let mut message = Vec::with_capacity(12);
        let comm_vec_bytes: Vec<u8> = combined_comm_vec
            .iter()
            .map(|x| x.compress().as_bytes().clone())
            .flatten()
            .collect();
        message.extend_from_slice(&aba_id.to_le_bytes());
        message.extend_from_slice(&round_number.to_le_bytes());
        message.extend_from_slice(&comm_vec_bytes);
        Signature::new_with_keypair(&message, keypair)
            .signature
            .as_bytes()[0]
            & 1
            == 1
    }
}
