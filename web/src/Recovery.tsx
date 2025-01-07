import { invoke } from "@tauri-apps/api/core";
import { useContext, useEffect, useState } from "react";
import toast from "react-hot-toast";
import Skeleton from "react-loading-skeleton";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useDebounce } from "use-debounce";
import CopyableCodeblock from "./components/CopyableCodeblock";
import User from "./components/User";
import { AuthContext } from "./components/AuthContext";
import { listen } from "@tauri-apps/api/event";

const Recovery = () => {
  const navigate = useNavigate();

  const [peers, setPeers] = useState<[string, number][]>([]);
  const [threshold, setThreshold] = useState<number>(0);
  const [selectedPeers, setSelectedPeers] = useState<boolean[]>([]);
  const [username, setUsername] = useState<string>("");
  const [debouncedUsername] = useDebounce(username, 500);
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!!debouncedUsername && debouncedUsername.length > 0) {
      invoke("get_recovery_addresses", { username: debouncedUsername })
        .then(() => {
          setPeers([]);
          setLoading(true);
        })
        .catch((err) => toast.error(err));
    }
  }, [debouncedUsername]);

  type TauriRecvAddr = {
    username: string;
    recovery_addresses: { string: number };
    threshold: number;
    error: string | null;
  };

  useEffect(() => {
    const registerListener = async () => {
      const unlisten = await listen<TauriRecvAddr>("recv_addr", (e) => {
        if (e.payload.username === debouncedUsername) {
          setLoading(false);
          if (e.payload.error !== null) {
            toast.error(e.payload.error);
          } else {
            setPeers(Object.entries(e.payload.recovery_addresses).sort());
            setThreshold(e.payload.threshold);
          }
        }
      });
      return unlisten;
    };

    const unlisten = registerListener();
    return () => {
      unlisten.then((fn) => fn && fn());
    };
  }, [debouncedUsername]);

  const { setIsLoggedIn } = useContext(AuthContext);

  const startRecovery = async () => {
    let recoveryNodes = new Map();
    for (const i in peers) {
      if (selectedPeers[i]) {
        recoveryNodes.set(peers[i][0], peers[i][1]);
      }
    }
    console.log(recoveryNodes);
    invoke("local_recovery", { username, password, recoveryNodes })
      .then(() => {
        /*invoke("tauri_save_local_envelope", { password })
          .then(() => {
            setIsLoggedIn(true); // if recovery was successful, can simply log in
            toast.success("Successfully recovered keypair");
            navigate("/");
          })
          .catch((err) => toast.error(err));*/
        console.log("TODO");
      })
      .catch((err) => toast.error(err));
  };

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
      <h1>Request recovery from peers</h1>
      <div>
        <div style={{ display: "flex", flexFlow: "column nowrap" }}>
          <label htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <hr />
          {debouncedUsername.length != 0 ? (
            !loading ? (
              <>
                {peers.map((peer, i) => (
                  <div
                    style={{
                      border: "2px solid var(--main)",
                      borderRadius: "1em",
                      padding: "1em",
                      marginBottom: "0.5em",
                      cursor: "pointer",
                      backgroundColor: selectedPeers[i]
                        ? "var(--main-light)"
                        : "auto",
                    }}
                    key={peer[0] + selectedPeers[i]}
                    onClick={() => {
                      setSelectedPeers((currentSelected) => {
                        let newSelected = currentSelected.slice();
                        newSelected[i] = !currentSelected[i];
                        return newSelected;
                      });
                    }}
                  >
                    <User user={peer[0]} />
                  </div>
                ))}
                <p>Select at least {threshold} recovery nodes to recover.</p>
              </>
            ) : (
              <Skeleton
                height={136}
                baseColor={"var(--background)"}
                highlightColor={"var(--main-light)"}
                borderRadius={"1em"}
                style={{ marginBottom: "1em" }}
              />
            )
          ) : null}
          <div>
            <button
              style={{
                float: "right",
                marginRight: 0,
                width: "fit-content",
              }}
              disabled={
                selectedPeers.filter((v) => v).length < threshold ||
                password.length === 0
              }
              title={
                selectedPeers.filter((v) => v).length < threshold
                  ? `Select ${threshold} or more recovery nodes to continue.`
                  : password.length === 0
                  ? "Enter your password to continue"
                  : undefined
              }
              onClick={startRecovery}
            >
              Done
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Recovery;
