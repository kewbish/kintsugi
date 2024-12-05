import { invoke } from "@tauri-apps/api/core";
import { useContext, useEffect, useState } from "react";
import toast from "react-hot-toast";
import Skeleton from "react-loading-skeleton";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useDebounce } from "use-debounce";
import CopyableCodeblock from "./components/CopyableCodeblock";
import User from "./components/User";
import { AuthContext } from "./components/AuthContext";

const Recovery = () => {
  const navigate = useNavigate();

  const [peers, setPeers] = useState<string[]>([]);
  const [selectedPeers, setSelectedPeers] = useState<boolean[]>([]);
  const [username, setUsername] = useState<string>("");
  const [password, setPassword] = useState("");

  useEffect(() => {
    invoke("get_peers")
      .then((resp) => {
        setPeers(resp as string[]);
        setSelectedPeers(new Array((resp as string[]).length).fill(false));
      })
      .catch((err) => toast.error(err));
  }, []);

  const { setIsLoggedIn } = useContext(AuthContext);

  const startRecovery = async () => {
    let recoveryNodes = new Map();
    let count = 1;
    for (const i in peers) {
      if (selectedPeers[i]) {
        recoveryNodes.set(count, peers[i]);
        count += 1;
      }
    }
    invoke("local_recovery", { username, password, recoveryNodes })
      .then(() => {
        invoke("tauri_save_local_envelope", { password })
          .then(() => {
            setIsLoggedIn(true); // if recovery was successful, can simply log in
            toast.success("Successfully recovered keypair");
            navigate("/");
          })
          .catch((err) => toast.error(err));
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
      {peers != undefined ? (
        peers.map((peer, i) => (
          <div
            style={{
              border: "2px solid var(--main)",
              borderRadius: "1em",
              padding: "1em",
              marginBottom: "0.5em",
              cursor: "pointer",
              backgroundColor: selectedPeers[i] ? "var(--main-light)" : "auto",
            }}
            key={peer + selectedPeers[i]}
            onClick={() => {
              setSelectedPeers((currentSelected) => {
                let newSelected = currentSelected.slice();
                newSelected[i] = !currentSelected[i];
                return newSelected;
              });
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
      <h2>Recover your account</h2>
      <div>
        <form
          action=""
          style={{ display: "flex", flexFlow: "column nowrap", gap: "1em" }}
        >
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
          <div>
            <button
              style={{
                float: "right",
                marginRight: 0,
                width: "fit-content",
              }}
              disabled={selectedPeers.filter((v) => v).length < 3}
              onClick={startRecovery}
            >
              Done
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Recovery;
