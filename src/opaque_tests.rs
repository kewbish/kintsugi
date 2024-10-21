#[cfg(test)]
mod opaque_test {
    use crate::opaque::{P2POpaqueError, P2POpaqueNode};

    #[test]
    fn test_happy_path() -> Result<(), P2POpaqueError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string())?;
        assert_eq!(reg_start_req.peer_id, "Alice".to_string());
        assert_eq!(reg_start_req.peer_public_key, node_1.keypair.public_key);

        let reg_start_resp = node_2.peer_registration_start(reg_start_req)?;
        assert_eq!(reg_start_resp.peer_public_key, node_2.keypair.public_key);

        let reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp)?;
        assert_eq!(reg_finish_req.peer_public_key, node_1.keypair.public_key);

        node_2.peer_registration_finish(reg_finish_req)?;
        assert!(node_2.peer_opaque_keys.contains_key("Alice"));
        assert!(node_2.envelopes.contains_key("Alice"));

        let login_start_req = node_1.local_login_start("password".to_string())?;
        assert_eq!(login_start_req.peer_id, "Alice".to_string());

        let login_start_resp = node_2.peer_login_start(login_start_req)?;
        assert_eq!(login_start_resp.peer_public_key, node_2.keypair.public_key);

        let keypair = node_1.local_login_finish("password".to_string(), login_start_resp)?;
        assert_eq!(keypair.public_key, node_1.keypair.public_key);
        assert_eq!(keypair.private_key, node_1.keypair.private_key);

        Ok(())
    }

    #[test]
    fn test_wrong_password() -> Result<(), P2POpaqueError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string())?;
        assert_eq!(reg_start_req.peer_id, "Alice".to_string());

        let reg_start_resp = node_2.peer_registration_start(reg_start_req)?;
        assert_eq!(reg_start_resp.peer_public_key, node_2.keypair.public_key);

        let reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp)?;
        assert_eq!(reg_finish_req.peer_public_key, node_1.keypair.public_key);

        node_2.peer_registration_finish(reg_finish_req)?;
        assert!(node_2.peer_opaque_keys.contains_key("Alice"));
        assert!(node_2.envelopes.contains_key("Alice"));

        // wrong password during start, corrected later

        let login_start_req = node_1.local_login_start("password2".to_string())?;
        assert_eq!(login_start_req.peer_id, "Alice".to_string());

        let login_start_resp = node_2.peer_login_start(login_start_req)?;
        assert_eq!(login_start_resp.peer_public_key, node_2.keypair.public_key);

        assert_eq!(
            node_1
                .local_login_finish("password".to_string(), login_start_resp)
                .unwrap_err(),
            P2POpaqueError::CryptoError("Decryption failed: aead::Error".to_string())
        );

        // wrong password during finish

        let login_start_req = node_1.local_login_start("password".to_string())?;
        assert_eq!(login_start_req.peer_id, "Alice".to_string());

        let login_start_resp = node_2.peer_login_start(login_start_req)?;
        assert_eq!(login_start_resp.peer_public_key, node_2.keypair.public_key);

        assert_eq!(
            node_1
                .local_login_finish("password2".to_string(), login_start_resp)
                .unwrap_err(),
            P2POpaqueError::CryptoError("Decryption failed: aead::Error".to_string())
        );

        // two diff wrong passwords during finish

        let login_start_req = node_1.local_login_start("password2".to_string())?;
        assert_eq!(login_start_req.peer_id, "Alice".to_string());

        let login_start_resp = node_2.peer_login_start(login_start_req)?;
        assert_eq!(login_start_resp.peer_public_key, node_2.keypair.public_key);

        assert_eq!(
            node_1
                .local_login_finish("password".to_string(), login_start_resp)
                .unwrap_err(),
            P2POpaqueError::CryptoError("Decryption failed: aead::Error".to_string())
        );

        Ok(())
    }

    #[test]
    fn test_serde_req_resps() -> Result<(), P2POpaqueError> {
        fn simulate_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>(message: T) -> T {
            let serialized =
                serde_json::to_string(&message).expect("JSON serialization of message failed");
            let deserialized =
                serde_json::from_str(&serialized).expect("JSON deserialization of message failed");
            deserialized
        }

        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let mut reg_start_req = node_1.local_registration_start("password".to_string())?;
        reg_start_req = simulate_serde(reg_start_req);

        let mut reg_start_resp = node_2.peer_registration_start(reg_start_req)?;
        reg_start_resp = simulate_serde(reg_start_resp);

        let mut reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp)?;
        reg_finish_req = simulate_serde(reg_finish_req);

        node_2.peer_registration_finish(reg_finish_req)?;

        let mut login_start_req = node_1.local_login_start("password".to_string())?;
        login_start_req = simulate_serde(login_start_req);

        let mut login_start_resp = node_2.peer_login_start(login_start_req)?;
        login_start_resp = simulate_serde(login_start_resp);

        let mut keypair = node_1.local_login_finish("password".to_string(), login_start_resp)?;
        keypair = simulate_serde(keypair);
        assert_eq!(keypair.public_key, node_1.keypair.public_key);
        assert_eq!(keypair.private_key, node_1.keypair.private_key);

        Ok(())
    }

    #[test]
    fn test_serde_node() -> Result<(), P2POpaqueError> {
        fn simulate_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>(node: T) -> T {
            let serialized =
                serde_json::to_string(&node).expect("JSON serialization of message failed");
            let deserialized =
                serde_json::from_str(&serialized).expect("JSON deserialization of message failed");
            deserialized
        }

        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string())?;

        let reg_start_resp = node_2.peer_registration_start(reg_start_req)?;

        node_1 = simulate_serde(node_1);
        let reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp)?;

        node_2 = simulate_serde(node_2);
        node_2.peer_registration_finish(reg_finish_req)?;

        node_1 = simulate_serde(node_1);
        let login_start_req = node_1.local_login_start("password".to_string())?;

        node_2 = simulate_serde(node_2);
        let login_start_resp = node_2.peer_login_start(login_start_req)?;

        node_1 = simulate_serde(node_1);
        let keypair = node_1.local_login_finish("password".to_string(), login_start_resp)?;
        assert_eq!(keypair.public_key, node_1.keypair.public_key);
        assert_eq!(keypair.private_key, node_1.keypair.private_key);

        Ok(())
    }

    #[test]
    fn test_nonexistent_envelope() -> Result<(), P2POpaqueError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string())?;

        let reg_start_resp = node_2.peer_registration_start(reg_start_req)?;

        let reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp)?;

        node_2.peer_registration_finish(reg_finish_req)?;

        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());
        let login_start_req = node_3.local_login_start("password".to_string())?;

        assert_eq!(
            node_2.peer_login_start(login_start_req).unwrap_err(),
            P2POpaqueError::RegistrationError
        );

        let mut login_start_req_2 = node_2.local_login_start("password".to_string())?;
        login_start_req_2.peer_id = "David".to_string();
        assert_eq!(
            node_2.peer_login_start(login_start_req_2).unwrap_err(),
            P2POpaqueError::RegistrationError
        );

        Ok(())
    }

    #[test]
    fn test_nonexistent_peer_finish() -> Result<(), P2POpaqueError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());
        let node_3 = P2POpaqueNode::new("Charlie".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string())?;

        let reg_start_resp = node_2.peer_registration_start(reg_start_req)?;

        assert_eq!(
            node_3
                .clone()
                .local_registration_finish("password".to_string(), reg_start_resp.clone())
                .unwrap_err(),
            P2POpaqueError::CryptoError("OPRF client not initialized".to_string())
        );

        let reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp)?;

        node_2.peer_registration_finish(reg_finish_req)?;

        let login_start_req = node_1.local_login_start("password".to_string())?;

        let login_start_resp = node_2.peer_login_start(login_start_req)?;

        assert_eq!(
            node_3
                .local_login_finish("password".to_string(), login_start_resp)
                .unwrap_err(),
            P2POpaqueError::CryptoError("OPRF client not initialized".to_string())
        );

        Ok(())
    }

    #[test]
    fn test_3_way_registration() -> Result<(), P2POpaqueError> {
        fn simulate_registration(
            n1: &mut P2POpaqueNode,
            n2: &mut P2POpaqueNode,
        ) -> Result<(), P2POpaqueError> {
            let reg_start_req = n1.local_registration_start("password".to_string())?;

            let reg_start_resp = n2.peer_registration_start(reg_start_req)?;

            let reg_finish_req =
                n1.local_registration_finish("password".to_string(), reg_start_resp)?;

            n2.peer_registration_finish(reg_finish_req)?;

            Ok(())
        }

        fn simulate_login(
            n1: &mut P2POpaqueNode,
            n2: &mut P2POpaqueNode,
        ) -> Result<(), P2POpaqueError> {
            let login_start_req = n1.local_login_start("password".to_string())?;

            let login_start_resp = n2.peer_login_start(login_start_req)?;

            let keypair = n1.local_login_finish("password".to_string(), login_start_resp)?;
            assert_eq!(keypair.public_key, n1.keypair.public_key);
            assert_eq!(keypair.private_key, n1.keypair.private_key);

            Ok(())
        }

        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());
        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());

        simulate_registration(&mut node_1, &mut node_2)?;
        simulate_registration(&mut node_2, &mut node_3)?;
        simulate_registration(&mut node_3, &mut node_1)?;

        simulate_registration(&mut node_2, &mut node_1)?;
        simulate_registration(&mut node_3, &mut node_2)?;
        simulate_registration(&mut node_1, &mut node_3)?;

        simulate_login(&mut node_1, &mut node_2)?;
        simulate_login(&mut node_2, &mut node_1)?;
        simulate_login(&mut node_1, &mut node_3)?;
        simulate_login(&mut node_3, &mut node_1)?;
        simulate_login(&mut node_2, &mut node_3)?;
        simulate_login(&mut node_3, &mut node_2)?;

        Ok(())
    }

    #[test]
    fn test_malicious_peer_reg_finish() -> Result<(), P2POpaqueError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string())?;

        let reg_start_resp = node_2.peer_registration_start(reg_start_req)?;

        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());
        let malicious_reg_start_req = node_3.local_registration_start("password".to_string())?;
        node_2.peer_registration_start(malicious_reg_start_req)?; // to initialize the OPRF client

        // finish registration with node 1's response, forge their peer ID and public key
        let mut malicious_reg_finish_req =
            node_3.local_registration_finish("password".to_string(), reg_start_resp.clone())?;
        malicious_reg_finish_req.peer_id = "Alice".to_string();
        malicious_reg_finish_req.peer_public_key = node_1.keypair.public_key;
        malicious_reg_finish_req.nonce = [1u8; 12];
        malicious_reg_finish_req.encrypted_envelope = b"Bad data!!".to_vec();

        assert_eq!(
            node_2
                .peer_registration_finish(malicious_reg_finish_req)
                .unwrap_err(),
            P2POpaqueError::CryptoError(
                "Could not verify signature of registration request".to_string()
            )
        );

        Ok(())
    }
}

#[cfg(test)]
mod local_encdec_test {
    use crate::{keypair::Keypair, opaque::Envelope};

    #[test]
    fn test_enc_dec_local_envelope() {
        let password = "password".to_string();
        let keypair = Keypair::new();
        let peer_id = "Alice".to_string();
        let peer_keypair = Keypair::new();
        let envelope = Envelope {
            keypair,
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
        assert_eq!(decrypted_envelope, envelope);
    }
}
