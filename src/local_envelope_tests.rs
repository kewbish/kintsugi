#[cfg(test)]
mod local_encdec_test {
    use crate::{keypair::Keypair, local_envelope::LocalEnvelope};

    #[test]
    fn test_enc_dec_local_envelope() {
        let password = "password".to_string();
        let keypair = Keypair::new();
        let peer_id = "Alice".to_string();
        let peer_keypair = Keypair::new();
        let envelope = LocalEnvelope {
            keypair,
            libp2p_keypair: libp2p::identity::ed25519::Keypair::generate(),
            peer_id,
            peer_public_key: peer_keypair.public_key,
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
        assert_eq!(decrypted_envelope.peer_public_key, envelope.peer_public_key);
        assert_eq!(decrypted_envelope.peer_id, envelope.peer_id);
    }
}
