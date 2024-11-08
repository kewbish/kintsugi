import { useState } from "react";
import Skeleton from "react-loading-skeleton";
import { Link } from "react-router-dom";
import CopyableCodeblock from "./components/CopyableCodeblock";
import User from "./components/User";

const PeerRecovery = () => {
  const PEERS = [
    "/dnsaddr/bootstrap.libp2p.io/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
  ];
  const [peers, setPeers] = useState(PEERS);
  const [selectedPeer, setSelectedPeer] = useState("");
  const [envelope, setEnvelope] = useState("");
  const [result, setResult] = useState("");

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        padding: "5em 0",
      }}
    >
      <Link to="/">&lt; back</Link>
      <h1>Peer Recovery</h1>
      <h2>Selected peer</h2>
      {peers != undefined ? (
        peers.map((peer, i) => (
          <div
            style={{
              border: "2px solid var(--main)",
              borderRadius: "1em",
              padding: "1em",
              marginBottom: "0.5em",
              cursor: "pointer",
              backgroundColor:
                selectedPeer === peer ? "var(--main-light)" : "auto",
            }}
            key={peer + selectedPeer}
            onClick={() => {
              setSelectedPeer(peer);
            }}
          >
            <User user={peer} />
          </div>
        ))
      ) : (
        <Skeleton
          height={136}
          baseColor={"var(--background)"}
          highlightColor={"var(--main-light)"}
          borderRadius={"1em"}
        />
      )}
      <hr style={{ margin: 0, marginTop: "0.5em", alignSelf: "stretch" }} />
      <p>
        Enter the envelope your contact has sent you, then send this output back
        via email, messenger, or another communication medium you trust.
      </p>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
          gridAutoRows: "auto",
          gap: "1em",
        }}
      >
        {selectedPeer !== "" ? (
          <div>
            <label htmlFor="envelope" style={{ display: "block" }}>
              {selectedPeer}'s envelope
            </label>
            <textarea
              id="envelope"
              value={envelope}
              onChange={(e) => setEnvelope(e.target.value)}
              style={{ resize: "none", maxWidth: "100%", width: "100%" }}
            />
          </div>
        ) : (
          <p>Select a peer to begin.</p>
        )}
        <div>
          <CopyableCodeblock contents={result} />
        </div>
      </div>
    </div>
  );
};

export default PeerRecovery;
