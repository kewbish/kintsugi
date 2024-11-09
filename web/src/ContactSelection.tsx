import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import User from "./components/User";

const ContactSelection = () => {
  const USERS = [
    "/dnsaddr/bootstrap.libp2p.io/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
  ];
  const [peers, setPeers] = useState(USERS);
  const navigate = useNavigate();
  const [currentInput, setCurrentInput] = useState("");

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        height: "100%",
        marginTop: "-5em",
      }}
    >
      <Link to="/">&lt; back</Link>
      <h1>Recovery contacts</h1>
      {peers.map((peer, i) => (
        <div key={peer}>
          <User
            user={peer}
            actions={
              <div style={{ paddingTop: ".5em" }}>
                <button
                  onClick={() => {
                    setPeers((currentPeers) =>
                      currentPeers.filter((_, index) => index != i)
                    );
                  }}
                >
                  Remove contact
                </button>
              </div>
            }
          />
          {i != peers.length - 1 ? <hr style={{ marginTop: "1em" }} /> : null}
        </div>
      ))}
      <div style={{ display: "flex", marginTop: "1em" }}>
        <input
          type="text"
          style={{ flexGrow: 1 }}
          value={currentInput}
          onChange={(e) => setCurrentInput(e.target.value)}
        />
        <button
          style={{ marginRight: 0 }}
          onClick={() => {
            setPeers((currentPeers) => {
              return [...currentPeers, currentInput];
            });
            setCurrentInput("");
          }}
        >
          Add contact
        </button>
      </div>
    </div>
  );
};

export default ContactSelection;
