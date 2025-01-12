#[cfg(test)]
mod local_encdec_test {
    use crate::kintsugi_lib::{keypair::Keypair, local_envelope::LocalEnvelope};

    #[test]
    fn test_enc_dec_local_envelope() {
        let password = "password".to_string();
        let keypair = Keypair::new();
        let peer_id = "Alice".to_string();
        let envelope = LocalEnvelope {
            keypair,
            username: peer_id.clone(),
        };

        let encrypted_envelope = envelope.clone().encrypt_w_password(password).unwrap();

        assert!(encrypted_envelope
            .clone()
            .decrypt_w_password("badpassword".to_string())
            .is_err());

        let decrypted_envelope = encrypted_envelope
            .decrypt_w_password("password".to_string())
            .unwrap();
        assert_eq!(decrypted_envelope.keypair, envelope.keypair);
    }
}
