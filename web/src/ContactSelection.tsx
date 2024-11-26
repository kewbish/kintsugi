import { invoke } from "@tauri-apps/api/core";
import { useState, useEffect } from "react";
import toast from "react-hot-toast";
import { Link } from "react-router-dom";
import User from "./components/User";

const ContactSelection = () => {
  const [peers, setPeers] = useState<string[]>([]);
  const [currentInput, setCurrentInput] = useState("");
  const [threshold, setThreshold] = useState(3);
  const [confirmedThreshold, setConfirmedThreshold] = useState(threshold);
  const [hasLoaded, setHasLoaded] = useState(false);

  useEffect(() => {
    invoke("get_peers")
      .then((resp) => {
        setPeers(resp as string[]);
        setHasLoaded(true);
      })
      .catch((err) => toast.error(err));
  }, []);

  useEffect(() => {
    if (hasLoaded) {
      let newRecoveryAddresses = new Map();
      for (const [i, address] of peers.entries()) {
        newRecoveryAddresses.set(address, i + 1);
      }
      invoke("local_refresh", {
        newRecoveryAddresses,
        newThreshold: confirmedThreshold - 1,
      })
        .then((_) => {
          toast.success("Successfully updated!");
        })
        .catch((err) => {
          toast.error(err);
        });
    }
  }, [peers, confirmedThreshold]);

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
      <hr style={{ marginTop: "1em" }} />
      <div style={{ marginTop: "1em" }}>
        <label htmlFor="threshold">Threshold</label>
        <div style={{ display: "flex" }}>
          <input
            type="number"
            style={{ flexGrow: 1 }}
            value={threshold}
            onChange={(e) => setThreshold(Number(e.target.value))}
            id="threshold"
          />
          <button
            style={{ marginRight: 0 }}
            onClick={() => setConfirmedThreshold(threshold)}
          >
            Update threshold
          </button>
        </div>
      </div>
    </div>
  );
};

export default ContactSelection;
