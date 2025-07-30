# Kintsugi

A decentralized, P2P implementation of the Kintsugi key recovery protocol.  
Built in Rust, with Tauri, React, and libp2p.  
Released under the [MIT License](./LICENSE).  
Written by [Emilie Ma](https://kewbi.sh).

Full paper available [on arXiv](https://arxiv.org/abs/2507.21122).

---

Key recovery is the process of regaining access to an account or end-to-end encrypted data in the case of device loss but not password loss. Existing E2EE key recovery methods, such as those deployed by Signal and WhatsApp, centralize trust by relying on servers administered by a single provider. This can be problematic for applications requiring metadata privacy or wanting to avoid a single party controlling user identities, for example. We propose Kintsugi, a decentralized recovery protocol that distributes trust over multiple recovery nodes, which could be servers run by independent parties, or end users in a peer-to-peer setting. To recover a user's keys, a threshold $t$ of recovery nodes must assist the user in decrypting a shared backup. Kintsugi is password-authenticated and protects against offline brute-force password guessing without requiring any specialized secure hardware. Kintsugi can tolerate the failure of up to a threshold $t$ of honest-but-curious colluding recovery nodes, as well as $n - t - 1$ offline nodes, and operates safely in an asynchronous network model where messages can be arbitrarily delayed.

## Demo

This Kintsugi implementation is accompanied by a demo Tauri app using React as a frontend and libp2p in the backend. This demo app is intended as a research preview and is not production-ready.

https://github.com/user-attachments/assets/32c89eb8-3aac-4015-aa36-e7ec3641cd30

- See [`web/`](./web) for the React frontend.
- See [`src/`](./src) for the Rust backend.
  - See [`src/main.rs`](./src/main.rs) for the libp2p network communication and Tauri app. The other modules in [`src/`](./src/) contain the various types and handlers required.
  - See [`src/kintsugi_lib/`](./src/kintsugi_lib/) for the library implementation. In particular, see [`opaque.rs`](./src/kintsugi_lib/opaque.rs) for the OPRF exchange and [`dpss.rs`](./src/kintsugi_lib/dpss.rs) for the dynamic proactive refresh.
  - Each module's associated tests can be found in the [`src/kintsugi_lib/`](./src/kintsugi_lib/) directory and can be run via `cargo test`.

To run the app:

- Clone this repository and run `cargo install`.
- Start the React Vite server with `cd web/ && npm install && npm run dev`.
- From the root of this repository, run `cargo run BOOTSTRAP 0`, `cargo run BOOTSTRAP 1`, etc. until `cargo run BOOTSTRAP 4`, which will start the default bootstrap nodes.
- Then, run `cargo run`, which will open the main Tauri app window.

## Caveats

Some non-essential aspects of the protocol have not been fully implemented in this prototype. These include:

- ZKP for the Paillier-encrypted values used in [Yurek et al., 2022](https://eprint.iacr.org/2022/971.pdf) — we use [ChaCha20Poly1305](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/index.html) for this implementation instead.
- Degree-checking of the ACSS polynomial.
- Reliable broadcast — we use libp2p's [request-response](https://docs.rs/libp2p-request-response/latest/libp2p_request_response/) behaviour instead.
- Multi-valued Validated Byzantine Agreement to agree on DPSS refresh subsets.
- Recovering persisted (bootstrap) node state after closing a node.
