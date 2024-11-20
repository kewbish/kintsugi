# Kintsugi

A decentralized, P2P implementation of the Kintsugi key recovery protocol.  
Built in Rust, with Tauri, React, and libp2p.  
Released under the [MIT License](./LICENSE).  
Written by [Emilie Ma](https://kewbi.sh).

---

Key recovery is the process of regaining access to an account or end-to-end encrypted data in the case of device loss but not password loss. Existing E2EE key recovery methods, such as those deployed by Signal and WhatsApp, centralize trust by relying on servers administered by a single provider. This can be problematic for applications requiring metadata privacy or wanting to avoid a single party controlling user identities, for example. We propose Kintsugi, a decentralized recovery protocol that distributes trust over multiple recovery nodes, which could be servers run by independent parties, or end users in a peer-to-peer setting. To recover a user's keys, a threshold $t$ of recovery nodes must assist the user in decrypting a shared backup. Kintsugi is password-authenticated and protects against offline brute-force password guessing without requiring any specialized secure hardware. Kintsugi can tolerate the failure of up to a threshold $t$ of honest-but-curious colluding recovery nodes, as well as $n - t - 1$ offline nodes, and operates safely in an asynchronous network model where messages can be arbitrarily delayed.

---

This Kintsugi implementation is accompagnied by a demo Tauri app using React as a frontend and libp2p in the backend. This demo app is a WIP.

- See [`web/`](./web) for the React frontend
- See [`src/`](./src) for the Rust backend
  - See [`src/main.rs`](./src/main.rs) for the network communication
  - See [`src/opaque.rs`](./src/opaque.rs) for the OPRF exchange
  - Each module's associated tests can be found in the [`src/`](./src) directory and can be run via `cargo run test`

To run the app, start the React Vite server with `cd web/ && npm run dev`. Then, run `cargo run`, which will open the Tauri app window.
