import { invoke } from "@tauri-apps/api/core";
import { useState, useEffect } from "react";
import toast from "react-hot-toast";
import { Link } from "react-router-dom";
import User from "./components/User";
import Skeleton from "react-loading-skeleton";
import { listen } from "@tauri-apps/api/event";

const ContactSelection = () => {
  const [peers, setPeers] = useState<string[]>([]);
  const [currentInput, setCurrentInput] = useState("");
  const [threshold, setThreshold] = useState(3);
  const [hasLoaded, setHasLoaded] = useState(false);

  useEffect(() => {
    invoke("get_peers")
      .then((resp) => {
        setPeers((resp as string[]).sort());
        setHasLoaded(true);
      })
      .catch((err) => toast.error(err));

    invoke("get_threshold")
      .then((resp) => setThreshold(resp as number))
      .catch((err) => toast.error(err));
  }, []);

  const startRefresh = (peers: string[], threshold: number) => {
    let newRecoveryAddresses = new Map();
    for (const [i, address] of peers.entries()) {
      newRecoveryAddresses.set(address, i + 1);
    }
    invoke("local_refresh", {
      newRecoveryAddresses,
      newThreshold: threshold,
    }).catch((err) => {
      toast.error(err);
    });
  };

  type TauriRefreshFinished = {
    username: string;
    error: string | null;
  };

  useEffect(() => {
    const registerListener = async () => {
      const unlisten = await listen<TauriRefreshFinished>("refresh", (_) => {
        toast.success("Updated recovery configuration!");
      });
      return unlisten;
    };

    const unlisten = registerListener();
    return () => {
      unlisten.then((fn) => fn && fn());
    };
  }, []);

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
      {hasLoaded ? (
        peers.map((peer, i) => (
          <div key={peer}>
            <User
              user={peer}
              actions={
                <div style={{ paddingTop: ".5em" }}>
                  <button
                    onClick={() => {
                      setPeers((currentPeers) => {
                        let newPeers = currentPeers.filter(
                          (_, index) => index != i
                        );
                        startRefresh(newPeers, threshold);
                        return newPeers;
                      });
                    }}
                  >
                    Remove contact
                  </button>
                </div>
              }
            />
            {i != peers.length - 1 ? <hr style={{ marginTop: "1em" }} /> : null}
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
              let newPeers = [...currentPeers, currentInput];
              startRefresh(newPeers, threshold);
              return newPeers;
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
            onClick={() => startRefresh(peers, threshold)}
          >
            Update threshold
          </button>
        </div>
      </div>
    </div>
  );
};

export default ContactSelection;
