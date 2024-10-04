#[cfg(test)]
mod test {
    use crate::P2POpaqueNode;

    #[test]
    fn test_happy_path() {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string());
        assert_eq!(reg_start_req.peer_id, "Alice".to_string());

        let reg_start_resp = node_2.peer_registration_start(reg_start_req);
        assert_eq!(reg_start_resp.peer_public_key, node_1.keypair.public_key);

        let reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp);
        assert_eq!(reg_finish_req.public_key, node_2.keypair.public_key);

        node_2.peer_registration_finish(reg_finish_req);
        assert!(node_2.peer_opaque_keys.contains_key("Alice"));
        assert!(node_2.envelopes.contains_key("Alice"));

        let login_start_req = node_1.local_login_start("password".to_string());
        assert_eq!(login_start_req.peer_id, "Alice".to_string());

        let login_start_resp = node_2.peer_login_start(login_start_req);
        assert_eq!(login_start_resp.peer_public_key, node_1.keypair.public_key);

        let keypair = node_1.local_login_finish("password".to_string(), login_start_resp);
        assert_eq!(keypair.public_key, node_1.keypair.public_key);
        assert_eq!(keypair.private_key, node_1.keypair.private_key);
    }

    #[test]
    fn test_wrong_password() {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string());
        assert_eq!(reg_start_req.peer_id, "Alice".to_string());

        let reg_start_resp = node_2.peer_registration_start(reg_start_req);
        assert_eq!(reg_start_resp.peer_public_key, node_1.keypair.public_key);

        let reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp);
        assert_eq!(reg_finish_req.public_key, node_2.keypair.public_key);

        node_2.peer_registration_finish(reg_finish_req);
        assert!(node_2.peer_opaque_keys.contains_key("Alice"));
        assert!(node_2.envelopes.contains_key("Alice"));

        // wrong password during start, corrected later

        let login_start_req = node_1.local_login_start("password2".to_string());
        assert_eq!(login_start_req.peer_id, "Alice".to_string());

        let login_start_resp = node_2.peer_login_start(login_start_req);
        assert_eq!(login_start_resp.peer_public_key, node_1.keypair.public_key);

        let panics = std::panic::catch_unwind(|| {
            node_1.local_login_finish("password".to_string(), login_start_resp)
        });
        assert!(panics.is_err());

        // wrong password during finish

        let login_start_req = node_1.local_login_start("password".to_string());
        assert_eq!(login_start_req.peer_id, "Alice".to_string());

        let login_start_resp = node_2.peer_login_start(login_start_req);
        assert_eq!(login_start_resp.peer_public_key, node_1.keypair.public_key);

        let panics = std::panic::catch_unwind(|| {
            node_1.local_login_finish("password2".to_string(), login_start_resp)
        });
        assert!(panics.is_err());

        // two diff wrong passwords during finish

        let login_start_req = node_1.local_login_start("password2".to_string());
        assert_eq!(login_start_req.peer_id, "Alice".to_string());

        let login_start_resp = node_2.peer_login_start(login_start_req);
        assert_eq!(login_start_resp.peer_public_key, node_1.keypair.public_key);

        let panics = std::panic::catch_unwind(|| {
            node_1.local_login_finish("password3".to_string(), login_start_resp)
        });
        assert!(panics.is_err());
    }

    #[test]
    fn test_serde_req_resps() {
        fn simulate_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>(message: T) -> T {
            let serialized =
                serde_json::to_string(&message).expect("JSON serialization of message failed");
            let deserialized =
                serde_json::from_str(&serialized).expect("JSON deserialization of message failed");
            deserialized
        }

        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let mut reg_start_req = node_1.local_registration_start("password".to_string());
        reg_start_req = simulate_serde(reg_start_req);

        let mut reg_start_resp = node_2.peer_registration_start(reg_start_req);
        reg_start_resp = simulate_serde(reg_start_resp);

        let mut reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp);
        reg_finish_req = simulate_serde(reg_finish_req);

        node_2.peer_registration_finish(reg_finish_req);

        let mut login_start_req = node_1.local_login_start("password".to_string());
        login_start_req = simulate_serde(login_start_req);

        let mut login_start_resp = node_2.peer_login_start(login_start_req);
        login_start_resp = simulate_serde(login_start_resp);

        let mut keypair = node_1.local_login_finish("password".to_string(), login_start_resp);
        keypair = simulate_serde(keypair);
        assert_eq!(keypair.public_key, node_1.keypair.public_key);
        assert_eq!(keypair.private_key, node_1.keypair.private_key);
    }

    #[test]
    fn test_serde_node() {
        fn simulate_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>(node: T) -> T {
            let serialized =
                serde_json::to_string(&node).expect("JSON serialization of message failed");
            let deserialized =
                serde_json::from_str(&serialized).expect("JSON deserialization of message failed");
            deserialized
        }

        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string());

        let reg_start_resp = node_2.peer_registration_start(reg_start_req);

        node_1 = simulate_serde(node_1);
        let reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp);

        node_2 = simulate_serde(node_2);
        node_2.peer_registration_finish(reg_finish_req);

        node_1 = simulate_serde(node_1);
        let login_start_req = node_1.local_login_start("password".to_string());

        node_2 = simulate_serde(node_2);
        let login_start_resp = node_2.peer_login_start(login_start_req);

        node_1 = simulate_serde(node_1);
        let keypair = node_1.local_login_finish("password".to_string(), login_start_resp);
        assert_eq!(keypair.public_key, node_1.keypair.public_key);
        assert_eq!(keypair.private_key, node_1.keypair.private_key);
    }

    #[test]
    fn test_nonexistent_envelope() {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string());

        let reg_start_resp = node_2.peer_registration_start(reg_start_req);

        let reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp);

        node_2.peer_registration_finish(reg_finish_req);

        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());
        let login_start_req = node_3.local_login_start("password".to_string());

        let panics = std::panic::catch_unwind(|| node_2.peer_login_start(login_start_req));
        assert!(panics.is_err());

        let mut login_start_req_2 = node_2.local_login_start("password".to_string());
        login_start_req_2.peer_id = "David".to_string();
        let panics = std::panic::catch_unwind(|| node_2.peer_login_start(login_start_req_2));
        assert!(panics.is_err());
    }

    #[test]
    fn test_nonexistent_peer_finish() {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());
        let node_3 = P2POpaqueNode::new("Charlie".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string());

        let reg_start_resp = node_2.peer_registration_start(reg_start_req);

        let panics = std::panic::catch_unwind(|| {
            node_3
                .clone()
                .local_registration_finish("password".to_string(), reg_start_resp.clone())
        });
        assert!(panics.is_err());
        let reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp);

        node_2.peer_registration_finish(reg_finish_req);

        let login_start_req = node_1.local_login_start("password".to_string());

        let login_start_resp = node_2.peer_login_start(login_start_req);

        let panics = std::panic::catch_unwind(|| {
            node_3.local_login_finish("password".to_string(), login_start_resp)
        });
        assert!(panics.is_err());
    }

    #[test]
    fn test_3_way_registration() {
        fn simulate_registration(n1: &mut P2POpaqueNode, n2: &mut P2POpaqueNode) {
            let reg_start_req = n1.local_registration_start("password".to_string());

            let reg_start_resp = n2.peer_registration_start(reg_start_req);

            let reg_finish_req =
                n1.local_registration_finish("password".to_string(), reg_start_resp);

            n2.peer_registration_finish(reg_finish_req);
        }

        fn simulate_login(n1: &mut P2POpaqueNode, n2: &mut P2POpaqueNode) {
            let login_start_req = n1.local_login_start("password".to_string());

            let login_start_resp = n2.peer_login_start(login_start_req);

            let keypair = n1.local_login_finish("password".to_string(), login_start_resp);
            assert_eq!(keypair.public_key, n1.keypair.public_key);
            assert_eq!(keypair.private_key, n1.keypair.private_key);
        }

        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());
        let mut node_3 = P2POpaqueNode::new("Charlie".to_string());

        simulate_registration(&mut node_1, &mut node_2);
        simulate_registration(&mut node_2, &mut node_3);
        simulate_registration(&mut node_3, &mut node_1);

        simulate_registration(&mut node_2, &mut node_1);
        simulate_registration(&mut node_3, &mut node_2);
        simulate_registration(&mut node_1, &mut node_3);

        simulate_login(&mut node_1, &mut node_2);
        simulate_login(&mut node_2, &mut node_1);
        simulate_login(&mut node_1, &mut node_3);
        simulate_login(&mut node_3, &mut node_1);
        simulate_login(&mut node_2, &mut node_3);
        simulate_login(&mut node_3, &mut node_2);
    }

    #[test]
    fn test_duplicate_reqs() {
        let mut node_1 = P2POpaqueNode::new("Alice".to_string());
        let mut node_2 = P2POpaqueNode::new("Bob".to_string());

        let reg_start_req = node_1.local_registration_start("password".to_string());

        let reg_start_resp = node_2.peer_registration_start(reg_start_req);

        // simulate node_1 not receiving the response and resending the req
        let reg_start_req_2 = node_1.local_registration_start("password2".to_string());
        let reg_start_resp_2 = node_2.peer_registration_start(reg_start_req_2);

        let reg_finish_req =
            node_1.local_registration_finish("password".to_string(), reg_start_resp);
        node_2.peer_registration_finish(reg_finish_req);

        let reg_finish_req_2 =
            node_1.local_registration_finish("password2".to_string(), reg_start_resp_2);
        node_2.peer_registration_finish(reg_finish_req_2); // duplicate finish should overwrite
                                                           // previous

        let login_start_req = node_1.local_login_start("password".to_string());
        let login_start_resp = node_2.peer_login_start(login_start_req);
        let panics = std::panic::catch_unwind(|| {
            node_1.local_login_finish("password".to_string(), login_start_resp)
        });
        assert!(panics.is_err());

        let login_start_req = node_1.local_login_start("password2".to_string());
        let login_start_resp = node_2.peer_login_start(login_start_req);
        let keypair = node_1.local_login_finish("password2".to_string(), login_start_resp);
        assert_eq!(keypair.public_key, node_1.keypair.public_key);
        assert_eq!(keypair.private_key, node_1.keypair.private_key);
    }

    /*
     * TODO:
     * - injecting messages into another exchange
     */
}

fn main() {}
