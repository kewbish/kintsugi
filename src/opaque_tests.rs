#[cfg(test)]
mod opaque_test {
    use std::collections::HashSet;

    use crate::opaque::{
        LoginStartNodeRequest, P2POpaqueError, P2POpaqueNode, RegStartNodeRequest,
    };

    #[test]
    fn test_happy_path() -> Result<(), P2POpaqueError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());
        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string())?;
        assert_eq!(reg_start_req.peer_id, "Alice".to_string());
        assert_eq!(reg_start_req.peer_public_key, node_1.keypair.public_key);

        let reg_start_node_2_req = RegStartNodeRequest {
            reg_start_req: reg_start_req.clone(),
            index: 2,
            other_indices: HashSet::from([1, 2, 3]),
        };
        let reg_start_resp_node_2 = node_2.peer_registration_start(reg_start_node_2_req)?;
        assert_eq!(
            reg_start_resp_node_2.peer_public_key,
            node_2.keypair.public_key
        );

        let reg_start_node_3_req = RegStartNodeRequest {
            reg_start_req,
            index: 3,
            other_indices: HashSet::from([1, 2, 3]),
        };
        let reg_start_resp_node_3 = node_3.peer_registration_start(reg_start_node_3_req)?;
        assert_eq!(
            reg_start_resp_node_3.peer_public_key,
            node_3.keypair.public_key
        );

        let reg_finish_req = node_1.local_registration_finish(
            "password".to_string(),
            [0u8; 64],
            Vec::from([reg_start_resp_node_2, reg_start_resp_node_3]),
        )?;
        assert_eq!(reg_finish_req[0].peer_public_key, node_1.keypair.public_key);

        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;
        assert!(node_2.peer_opaque_keys.contains_key("Alice"));
        assert!(node_2.envelopes.contains_key("Alice"));

        node_3.peer_registration_finish(reg_finish_req.get(1).unwrap().clone())?;
        assert!(node_3.peer_opaque_keys.contains_key("Alice"));
        assert!(node_3.envelopes.contains_key("Alice"));

        let login_start_req = node_1.local_login_start("password".to_string())?;
        assert_eq!(login_start_req.peer_id, "Alice".to_string());

        let login_start_req_node_2 = LoginStartNodeRequest {
            login_start_req: login_start_req.clone(),
            index: 2,
            other_indices: HashSet::from([1, 2, 3]),
        };
        let login_start_resp_node_2 = node_2.peer_login_start(login_start_req_node_2)?;
        assert_eq!(
            login_start_resp_node_2.peer_public_key,
            node_2.keypair.public_key
        );

        let login_start_req_node_3 = LoginStartNodeRequest {
            login_start_req: login_start_req.clone(),
            index: 3,
            other_indices: HashSet::from([1, 2, 3]),
        };
        let login_start_resp_node_3 = node_3.peer_login_start(login_start_req_node_3)?;
        assert_eq!(
            login_start_resp_node_3.peer_public_key,
            node_3.keypair.public_key
        );

        let (keypair, _) = node_1.local_login_finish(
            "password".to_string(),
            [0u8; 64],
            Vec::from([login_start_resp_node_2, login_start_resp_node_3]),
        )?;
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

        let reg_start_node_2_req = RegStartNodeRequest {
            reg_start_req,
            index: 2,
            other_indices: HashSet::from([1, 2]),
        };
        let reg_start_resp = node_2.peer_registration_start(reg_start_node_2_req)?;
        assert_eq!(reg_start_resp.peer_public_key, node_2.keypair.public_key);

        let reg_finish_req = node_1.local_registration_finish(
            "password".to_string(),
            [0u8; 64],
            Vec::from([reg_start_resp]),
        )?;
        assert_eq!(
            reg_finish_req.get(0).unwrap().peer_public_key,
            node_1.keypair.public_key
        );

        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;
        assert!(node_2.peer_opaque_keys.contains_key("Alice"));
        assert!(node_2.envelopes.contains_key("Alice"));

        // wrong password during start, corrected later

        let login_start_req = node_1.local_login_start("password2".to_string())?;
        assert_eq!(login_start_req.peer_id, "Alice".to_string());

        let login_start_node_2_req = LoginStartNodeRequest {
            login_start_req,
            index: 2,
            other_indices: HashSet::from([1, 2]),
        };
        let login_start_resp = node_2.peer_login_start(login_start_node_2_req)?;
        assert_eq!(login_start_resp.peer_public_key, node_2.keypair.public_key);

        assert_eq!(
            node_1
                .local_login_finish(
                    "password".to_string(),
                    [0u8; 64],
                    Vec::from([login_start_resp])
                )
                .unwrap_err(),
            P2POpaqueError::CryptoError("Decryption failed: aead::Error".to_string())
        );

        // two diff wrong passwords during finish

        let login_start_req = node_1.local_login_start("password2".to_string())?;
        assert_eq!(login_start_req.peer_id, "Alice".to_string());

        let login_start_node_2_req = LoginStartNodeRequest {
            login_start_req,
            index: 2,
            other_indices: HashSet::from([1, 2]),
        };
        let login_start_resp = node_2.peer_login_start(login_start_node_2_req)?;
        assert_eq!(login_start_resp.peer_public_key, node_2.keypair.public_key);

        assert_eq!(
            node_1
                .local_login_finish(
                    "password3".to_string(),
                    [0u8; 64],
                    Vec::from([login_start_resp])
                )
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

        let reg_start_node_2_req = RegStartNodeRequest {
            reg_start_req,
            index: 2,
            other_indices: HashSet::from([1, 2]),
        };
        let mut reg_start_resp = node_2.peer_registration_start(reg_start_node_2_req)?;
        reg_start_resp = simulate_serde(reg_start_resp);

        let mut reg_finish_req = node_1.local_registration_finish(
            "password".to_string(),
            [0u8; 64],
            Vec::from([reg_start_resp]),
        )?;
        reg_finish_req = simulate_serde(reg_finish_req);

        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;

        let mut login_start_req = node_1.local_login_start("password".to_string())?;
        login_start_req = simulate_serde(login_start_req);

        let login_start_node_2_req = LoginStartNodeRequest {
            login_start_req,
            index: 2,
            other_indices: HashSet::from([1, 2]),
        };
        let mut login_start_resp = node_2.peer_login_start(login_start_node_2_req)?;
        login_start_resp = simulate_serde(login_start_resp);

        let (mut keypair, _) = node_1.local_login_finish(
            "password".to_string(),
            [0u8; 64],
            Vec::from([login_start_resp]),
        )?;
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

        let reg_start_node_2_req = RegStartNodeRequest {
            reg_start_req,
            index: 2,
            other_indices: HashSet::from([1, 2]),
        };
        let reg_start_resp = node_2.peer_registration_start(reg_start_node_2_req)?;

        node_1 = simulate_serde(node_1);
        let reg_finish_req = node_1.local_registration_finish(
            "password".to_string(),
            [0u8; 64],
            Vec::from([reg_start_resp]),
        )?;

        node_2 = simulate_serde(node_2);
        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;

        node_1 = simulate_serde(node_1);
        let login_start_req = node_1.local_login_start("password".to_string())?;

        node_2 = simulate_serde(node_2);
        let login_start_node_2_req = LoginStartNodeRequest {
            login_start_req,
            index: 2,
            other_indices: HashSet::from([1, 2]),
        };
        let login_start_resp = node_2.peer_login_start(login_start_node_2_req)?;

        node_1 = simulate_serde(node_1);
        let (keypair, _) = node_1.local_login_finish(
            "password".to_string(),
            [0u8; 64],
            Vec::from([login_start_resp]),
        )?;
        assert_eq!(keypair.public_key, node_1.keypair.public_key);
        assert_eq!(keypair.private_key, node_1.keypair.private_key);

        Ok(())
    }

    #[test]
    fn test_nonexistent_envelope() -> Result<(), P2POpaqueError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string())?;

        let reg_start_node_2_req = RegStartNodeRequest {
            reg_start_req,
            index: 2,
            other_indices: HashSet::from([1, 2]),
        };
        let reg_start_resp = node_2.peer_registration_start(reg_start_node_2_req)?;

        let reg_finish_req = node_1.local_registration_finish(
            "password".to_string(),
            [0u8; 64],
            Vec::from([reg_start_resp]),
        )?;

        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;

        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());
        let login_start_req = node_3.local_login_start("password".to_string())?;

        let login_start_node_3_req = LoginStartNodeRequest {
            login_start_req,
            index: 3,
            other_indices: HashSet::from([1, 2]),
        };
        assert_eq!(
            node_2.peer_login_start(login_start_node_3_req).unwrap_err(),
            P2POpaqueError::RegistrationError
        );

        let mut login_start_req_2 = node_2.local_login_start("password".to_string())?;
        login_start_req_2.peer_id = "David".to_string();
        let login_start_node_2_req = LoginStartNodeRequest {
            login_start_req: login_start_req_2,
            index: 2,
            other_indices: HashSet::from([1, 2]),
        };
        assert_eq!(
            node_2.peer_login_start(login_start_node_2_req).unwrap_err(),
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

        let reg_start_node_2_req = RegStartNodeRequest {
            reg_start_req,
            index: 2,
            other_indices: HashSet::from([1, 2]),
        };
        let reg_start_resp = node_2.peer_registration_start(reg_start_node_2_req)?;

        assert_eq!(
            node_3
                .clone()
                .local_registration_finish(
                    "password".to_string(),
                    [0u8; 64],
                    Vec::from([reg_start_resp.clone()])
                )
                .unwrap_err(),
            P2POpaqueError::CryptoError("OPRF client not initialized".to_string())
        );

        let reg_finish_req = node_1.local_registration_finish(
            "password".to_string(),
            [0u8; 64],
            Vec::from([reg_start_resp]),
        )?;

        node_2.peer_registration_finish(reg_finish_req.get(0).unwrap().clone())?;

        let login_start_req = node_1.local_login_start("password".to_string())?;

        let login_start_node_2_req = LoginStartNodeRequest {
            login_start_req,
            index: 2,
            other_indices: HashSet::from([1, 2]),
        };
        let login_start_resp = node_2.peer_login_start(login_start_node_2_req)?;

        assert_eq!(
            node_3
                .local_login_finish(
                    "password".to_string(),
                    [0u8; 64],
                    Vec::from([login_start_resp])
                )
                .unwrap_err(),
            P2POpaqueError::CryptoError("OPRF client not initialized".to_string())
        );

        Ok(())
    }

    #[test]
    fn test_malicious_peer_reg_finish() -> Result<(), P2POpaqueError> {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string())?;

        let reg_start_node_2_req = RegStartNodeRequest {
            reg_start_req,
            index: 2,
            other_indices: HashSet::from([1, 2]),
        };
        let reg_start_resp = node_2.peer_registration_start(reg_start_node_2_req)?;

        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());
        let malicious_reg_start_req = node_3.local_registration_start("password".to_string())?;
        let malicious_reg_start_node_req = RegStartNodeRequest {
            reg_start_req: malicious_reg_start_req,
            index: 3,
            other_indices: HashSet::from([1, 2, 3]),
        };
        node_2.peer_registration_start(malicious_reg_start_node_req)?; // to initialize the OPRF client

        // finish registration with node 1's response, forge their peer ID and public key
        let mut malicious_reg_finish_req = node_3.local_registration_finish(
            "password".to_string(),
            [0u8; 64],
            Vec::from([reg_start_resp]),
        )?;
        malicious_reg_finish_req.get_mut(0).unwrap().peer_id = "Alice".to_string();
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
            P2POpaqueError::CryptoError(
                "Could not verify signature of registration request".to_string()
            )
        );

        Ok(())
    }
}
