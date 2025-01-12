#[cfg(test)]
mod opaque_test {
    use curve25519_dalek::Scalar;

    use crate::{
        kintsugi_lib::error::KintsugiError, kintsugi_lib::opaque::P2POpaqueNode,
        kintsugi_lib::util::i32_to_scalar,
    };

    #[test]
    fn test_happy_path() -> Result<(), KintsugiError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());
        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());

        let reg_start_req_1 =
            node_1.local_registration_start("password".to_string(), "Bob".to_string())?;
        assert_eq!(reg_start_req_1.user_username, "Alice".to_string());
        assert_eq!(reg_start_req_1.peer_public_key, node_1.keypair.public_key);

        let reg_start_resp_node_2 =
            node_2.peer_registration_start(reg_start_req_1, i32_to_scalar(1), 2)?;
        assert_eq!(
            reg_start_resp_node_2.peer_public_key,
            node_2.keypair.public_key
        );

        let reg_start_req_2 =
            node_1.local_registration_start("password".to_string(), "Charlie".to_string())?;
        let reg_start_resp_node_3 =
            node_3.peer_registration_start(reg_start_req_2, i32_to_scalar(1), 3)?;
        assert_eq!(
            reg_start_resp_node_3.peer_public_key,
            node_3.keypair.public_key
        );

        let reg_finish_req = node_1
            .local_registration_finish(Vec::from([reg_start_resp_node_2, reg_start_resp_node_3]))?;
        assert_eq!(reg_finish_req[0].peer_public_key, node_1.keypair.public_key);

        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;
        assert!(node_2.peer_opaque_keys.contains_key("Alice"));
        assert!(node_2.envelopes.contains_key("Alice"));

        node_3.peer_registration_finish(reg_finish_req.get(1).unwrap().clone())?;
        assert!(node_3.peer_opaque_keys.contains_key("Alice"));
        assert!(node_3.envelopes.contains_key("Alice"));

        let login_start_req_1 =
            node_1.local_login_start("password".to_string(), "Bob".to_string())?;
        assert_eq!(login_start_req_1.user_username, "Alice".to_string());

        let login_start_resp_node_2 =
            node_2.peer_login_start(login_start_req_1, i32_to_scalar(1), 2)?;
        assert_eq!(
            login_start_resp_node_2.peer_public_key,
            node_2.keypair.public_key
        );

        let login_start_req_2 =
            node_1.local_login_start("password".to_string(), "Charlie".to_string())?;
        let login_start_resp_node_3 =
            node_3.peer_login_start(login_start_req_2, i32_to_scalar(1), 3)?;
        assert_eq!(
            login_start_resp_node_3.peer_public_key,
            node_3.keypair.public_key
        );

        let keypair = node_1.local_login_finish(Vec::from([
            login_start_resp_node_2,
            login_start_resp_node_3,
        ]))?;
        assert_eq!(keypair.public_key, node_1.keypair.public_key);
        assert_eq!(keypair.private_key, node_1.keypair.private_key);

        Ok(())
    }

    #[test]
    fn test_wrong_password() -> Result<(), KintsugiError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req =
            node_1.local_registration_start("password".to_string(), "Bob".to_string())?;
        assert_eq!(reg_start_req.user_username, "Alice".to_string());

        let reg_start_resp = node_2.peer_registration_start(reg_start_req, i32_to_scalar(1), 2)?;
        assert_eq!(reg_start_resp.peer_public_key, node_2.keypair.public_key);

        let reg_finish_req = node_1.local_registration_finish(Vec::from([reg_start_resp]))?;
        assert_eq!(
            reg_finish_req.get(0).unwrap().peer_public_key,
            node_1.keypair.public_key
        );

        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;
        assert!(node_2.peer_opaque_keys.contains_key("Alice"));
        assert!(node_2.envelopes.contains_key("Alice"));

        // wrong password during start

        let login_start_req =
            node_1.local_login_start("password2".to_string(), "Bob".to_string())?;
        assert_eq!(login_start_req.user_username, "Alice".to_string());

        let login_start_resp =
            node_2.peer_login_start(login_start_req.clone(), i32_to_scalar(1), 2)?;
        assert_eq!(login_start_resp.peer_public_key, node_2.keypair.public_key);

        assert_eq!(
            node_1
                .local_login_finish(Vec::from([login_start_resp]))
                .unwrap_err(),
            KintsugiError::CryptoError("Decryption failed: aead::Error".to_string())
        );

        Ok(())
    }

    #[test]
    fn test_serde_req_resps() -> Result<(), KintsugiError> {
        fn simulate_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>(message: T) -> T {
            let serialized =
                serde_json::to_string(&message).expect("JSON serialization of message failed");
            let deserialized =
                serde_json::from_str(&serialized).expect("JSON deserialization of message failed");
            deserialized
        }

        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let mut reg_start_req =
            node_1.local_registration_start("password".to_string(), "Bob".to_string())?;
        reg_start_req = simulate_serde(reg_start_req);

        let mut reg_start_resp =
            node_2.peer_registration_start(reg_start_req, i32_to_scalar(1), 2)?;
        reg_start_resp = simulate_serde(reg_start_resp);

        let mut reg_finish_req = node_1.local_registration_finish(Vec::from([reg_start_resp]))?;
        reg_finish_req = simulate_serde(reg_finish_req);

        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;

        let mut login_start_req =
            node_1.local_login_start("password".to_string(), "Bob".to_string())?;
        login_start_req = simulate_serde(login_start_req);

        let mut login_start_resp = node_2.peer_login_start(login_start_req, i32_to_scalar(1), 2)?;
        login_start_resp = simulate_serde(login_start_resp);

        let mut keypair = node_1.local_login_finish(Vec::from([login_start_resp]))?;
        keypair = simulate_serde(keypair);
        assert_eq!(keypair.public_key, node_1.keypair.public_key);
        assert_eq!(keypair.private_key, node_1.keypair.private_key);

        Ok(())
    }

    #[test]
    fn test_serde_node() -> Result<(), KintsugiError> {
        fn simulate_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>(node: T) -> T {
            let serialized =
                serde_json::to_string(&node).expect("JSON serialization of message failed");
            let deserialized =
                serde_json::from_str(&serialized).expect("JSON deserialization of message failed");
            deserialized
        }

        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req =
            node_1.local_registration_start("password".to_string(), "Bob".to_string())?;

        let reg_start_resp = node_2.peer_registration_start(reg_start_req, i32_to_scalar(1), 2)?;

        node_1 = simulate_serde(node_1);
        let reg_finish_req = node_1.local_registration_finish(Vec::from([reg_start_resp]))?;

        node_2 = simulate_serde(node_2);
        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;

        node_1 = simulate_serde(node_1);
        let login_start_req =
            node_1.local_login_start("password".to_string(), "Bob".to_string())?;

        node_2 = simulate_serde(node_2);
        let login_start_resp = node_2.peer_login_start(login_start_req, i32_to_scalar(1), 2)?;

        node_1 = simulate_serde(node_1);
        let keypair = node_1.local_login_finish(Vec::from([login_start_resp]))?;
        assert_eq!(keypair.public_key, node_1.keypair.public_key);
        assert_eq!(keypair.private_key, node_1.keypair.private_key);

        Ok(())
    }

    #[test]
    fn test_nonexistent_envelope() -> Result<(), KintsugiError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req =
            node_1.local_registration_start("password".to_string(), "Bob".to_string())?;

        let reg_start_resp = node_2.peer_registration_start(reg_start_req, i32_to_scalar(1), 2)?;

        let reg_finish_req = node_1.local_registration_finish(Vec::from([reg_start_resp]))?;

        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;

        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());
        let login_start_req =
            node_3.local_login_start("password".to_string(), "Charlie".to_string())?;

        assert_eq!(
            node_2
                .peer_login_start(login_start_req.clone(), i32_to_scalar(1), 3,)
                .unwrap_err(),
            KintsugiError::RegistrationError
        );

        let mut login_start_req_2 =
            node_2.local_login_start("password".to_string(), "Bob".to_string())?;
        login_start_req_2.user_username = "David".to_string();
        assert_eq!(
            node_2
                .peer_login_start(login_start_req, i32_to_scalar(1), 2,)
                .unwrap_err(),
            KintsugiError::RegistrationError
        );

        Ok(())
    }

    #[test]
    fn test_nonexistent_peer_finish() -> Result<(), KintsugiError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());
        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());

        let reg_start_req =
            node_1.local_registration_start("password".to_string(), "Bob".to_string())?;

        let reg_start_resp = node_2.peer_registration_start(reg_start_req, i32_to_scalar(1), 2)?;

        assert_eq!(
            node_3
                .clone()
                .local_registration_finish(Vec::from([reg_start_resp.clone()]))
                .unwrap_err(),
            KintsugiError::CryptoError("OPRF client not initialized".to_string())
        );

        let reg_finish_req = node_1.local_registration_finish(Vec::from([reg_start_resp]))?;

        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;

        let login_start_req =
            node_1.local_login_start("password".to_string(), "Charlie".to_string())?;

        let login_start_resp = node_2.peer_login_start(login_start_req, i32_to_scalar(1), 2)?;

        assert_eq!(
            node_3
                .local_login_finish(Vec::from([login_start_resp]))
                .unwrap_err(),
            KintsugiError::CryptoError("OPRF client not initialized".to_string())
        );

        Ok(())
    }

    #[test]
    fn test_malicious_peer_reg_finish() -> Result<(), KintsugiError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req =
            node_1.local_registration_start("password".to_string(), "Bob".to_string())?;

        let reg_start_resp = node_2.peer_registration_start(reg_start_req, i32_to_scalar(1), 2)?;

        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());
        let malicious_reg_start_req =
            node_3.local_registration_start("password".to_string(), "Bob".to_string())?;
        node_2.peer_registration_start(malicious_reg_start_req, i32_to_scalar(1), 3)?; // to initialize the OPRF client

        // finish registration with node 1's response, forge their peer ID and public key
        let mut malicious_reg_finish_req =
            node_3.local_registration_finish(Vec::from([reg_start_resp]))?;
        malicious_reg_finish_req.get_mut(0).unwrap().user_username = "Alice".to_string();
        malicious_reg_finish_req.get_mut(0).unwrap().node_username = "Bob".to_string();
        malicious_reg_finish_req.get_mut(0).unwrap().peer_public_key = node_1.keypair.public_key;
        malicious_reg_finish_req.get_mut(0).unwrap().nonce = [1u8; 12];
        malicious_reg_finish_req
            .get_mut(0)
            .unwrap()
            .encrypted_envelope = b"Bad data!!".to_vec();

        assert_eq!(
            node_2
                .peer_registration_finish(malicious_reg_finish_req.get(0).unwrap().clone())
                .unwrap_err(),
            KintsugiError::CryptoError(
                "Could not verify signature of registration request".to_string()
            )
        );

        Ok(())
    }

    #[test]
    fn test_opaque_with_refresh() -> Result<(), KintsugiError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());
        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());
        let mut node_4 = P2POpaqueNode::new("David".to_string());

        let reg_start_req_1 =
            node_1.local_registration_start("password".to_string(), "Bob".to_string())?;
        assert_eq!(reg_start_req_1.user_username, "Alice".to_string());
        assert_eq!(reg_start_req_1.peer_public_key, node_1.keypair.public_key);

        let reg_start_resp_node_2 = node_2.peer_registration_start(
            reg_start_req_1,
            Scalar::from_canonical_bytes([
                254, 121, 42, 108, 162, 108, 116, 113, 239, 133, 17, 167, 63, 22, 180, 32, 229, 42,
                88, 137, 252, 231, 254, 251, 31, 137, 204, 144, 189, 94, 189, 2,
            ])
            .unwrap(),
            1,
        )?;
        assert_eq!(
            reg_start_resp_node_2.peer_public_key,
            node_2.keypair.public_key
        );

        let reg_start_req_2 =
            node_1.local_registration_start("password".to_string(), "Charlie".to_string())?;
        let reg_start_resp_node_3 = node_3.peer_registration_start(
            reg_start_req_2,
            Scalar::from_canonical_bytes([
                238, 177, 64, 234, 2, 242, 25, 85, 80, 148, 2, 97, 18, 149, 146, 4, 141, 36, 29, 2,
                19, 207, 189, 74, 140, 86, 80, 90, 103, 230, 236, 14,
            ])
            .unwrap(),
            2,
        )?;
        assert_eq!(
            reg_start_resp_node_3.peer_public_key,
            node_3.keypair.public_key
        );

        let reg_start_req_3 =
            node_1.local_registration_start("password".to_string(), "David".to_string())?;
        let reg_start_resp_node_4 = node_4.peer_registration_start(
            reg_start_req_3,
            Scalar::from_canonical_bytes([
                29, 42, 140, 27, 156, 142, 30, 42, 157, 187, 220, 147, 13, 42, 248, 41, 149, 162,
                202, 200, 9, 52, 236, 144, 178, 178, 25, 17, 112, 48, 236, 5,
            ])
            .unwrap(),
            3,
        )?;
        assert_eq!(
            reg_start_resp_node_4.peer_public_key,
            node_4.keypair.public_key
        );

        let reg_finish_req = node_1.local_registration_finish(Vec::from([
            reg_start_resp_node_2,
            reg_start_resp_node_3,
            reg_start_resp_node_4,
        ]))?;
        assert_eq!(reg_finish_req[0].peer_public_key, node_1.keypair.public_key);

        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;
        assert!(node_2.peer_opaque_keys.contains_key("Alice"));
        assert!(node_2.envelopes.contains_key("Alice"));

        node_3.peer_registration_finish(reg_finish_req.get(1).unwrap().clone())?;
        assert!(node_3.peer_opaque_keys.contains_key("Alice"));
        assert!(node_3.envelopes.contains_key("Alice"));

        node_4.peer_registration_finish(reg_finish_req.get(2).unwrap().clone())?;
        assert!(node_4.peer_opaque_keys.contains_key("Alice"));
        assert!(node_4.envelopes.contains_key("Alice"));

        let login_start_req_1 =
            node_1.local_login_start("password".to_string(), "Bob".to_string())?;
        assert_eq!(login_start_req_1.user_username, "Alice".to_string());
        let login_start_resp_node_2 = node_2.peer_login_start(
            login_start_req_1,
            Scalar::from_canonical_bytes([
                96, 163, 184, 5, 226, 120, 56, 162, 100, 233, 172, 99, 92, 45, 144, 230, 112, 212,
                117, 163, 106, 107, 90, 86, 158, 255, 204, 94, 44, 173, 58, 1,
            ])
            .unwrap(),
            1,
        )?;
        assert_eq!(
            login_start_resp_node_2.peer_public_key,
            node_2.keypair.public_key
        );

        let login_start_req_2 =
            node_1.local_login_start("password".to_string(), "Charlie".to_string())?;
        let login_start_resp_node_3 = node_3.peer_login_start(
            login_start_req_2,
            Scalar::from_canonical_bytes([
                153, 28, 60, 176, 20, 45, 30, 21, 162, 8, 97, 27, 102, 185, 5, 37, 68, 243, 111,
                232, 14, 88, 5, 8, 207, 180, 11, 9, 230, 192, 23, 1,
            ])
            .unwrap(),
            2,
        )?;
        assert_eq!(
            login_start_resp_node_3.peer_public_key,
            node_3.keypair.public_key
        );

        let login_start_req_3 =
            node_1.local_login_start("password".to_string(), "David".to_string())?;
        let login_start_resp_node_4 = node_4.peer_login_start(
            login_start_req_3,
            Scalar::from_canonical_bytes([
                210, 149, 191, 90, 71, 225, 3, 136, 223, 39, 21, 211, 111, 69, 123, 99, 23, 18,
                106, 45, 179, 68, 176, 185, 255, 105, 74, 179, 159, 212, 244, 0,
            ])
            .unwrap(),
            3,
        )?;
        assert_eq!(
            login_start_resp_node_4.peer_public_key,
            node_4.keypair.public_key
        );

        let keypair = node_1.local_login_finish(Vec::from([
            login_start_resp_node_2,
            login_start_resp_node_3,
            login_start_resp_node_4,
        ]))?;
        assert_eq!(keypair.public_key, node_1.keypair.public_key);
        assert_eq!(keypair.private_key, node_1.keypair.private_key);

        Ok(())
    }
}
