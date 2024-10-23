use curve25519_dalek::Scalar;

use crate::{keypair::Keypair, signature::Signature};

pub struct Coin {}

impl Coin {
    pub fn get_value(keypair: Keypair, aba_id: i32, round_number: usize) -> Scalar {
        let mut message = Vec::with_capacity(12);
        message.extend_from_slice(&aba_id.to_le_bytes());
        message.extend_from_slice(&round_number.to_le_bytes());
        Signature::new_with_keypair(&message, keypair).signature
    }
}
