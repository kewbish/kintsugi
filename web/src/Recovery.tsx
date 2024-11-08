import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import Skeleton from "react-loading-skeleton";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useDebounce } from "use-debounce";
import CopyableCodeblock from "./components/CopyableCodeblock";
import User from "./components/User";

const Recovery = () => {
  const navigate = useNavigate();

  const PEERS = [
    "/dnsaddr/bootstrap.libp2p.io/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
  ];
  const [peers, setPeers] = useState(PEERS);
  const [isFirstStep, setIsFirstStep] = useState(true);
  const [password, setPassword] = useState("");
  const [debouncedPassword] = useDebounce(password, 1000);
  const [result, setResult] = useState("");
  const [contactOutputs, setContactOutputs] = useState<string[]>([]);
  const [debouncedContactOutputs] = useDebounce(contactOutputs, 1000);
  const [secondResult, setSecondResult] = useState("");
  const [selectedPeers, setSelectedPeers] = useState<boolean[]>([]);

  useEffect(() => {
    if (!debouncedPassword) {
      return;
    }
    invoke("local_login_start", { password })
      .then((resp) => {
        setResult(resp as string);
      })
      .catch((err) => toast.error(err));
  }, [debouncedPassword]);

  useEffect(() => {
    if (
      !debouncedContactOutputs.length ||
      !debouncedContactOutputs.some((output) => output !== "")
    ) {
      return;
    }
    invoke("local_login_finish", {
      password,
      peerResp: debouncedContactOutputs,
    })
      .then((resp) => {
        setSecondResult(resp as string);
      })
      .catch((err) => toast.error(err));
  }, [debouncedContactOutputs]);

  useEffect(() => {
    setSelectedPeers(new Array(peers.length).fill(false));
  }, [peers]);

  useEffect(() => {
    if (contactOutputs.length === 0) {
      setContactOutputs(new Array(peers.length).fill(""));
    }
  }, [peers, contactOutputs]);

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
      <h2>Calculator</h2>
      {isFirstStep ? (
        <>
          <p>
            Send this output to each recovery contact via email, messenger, or
            another communication medium you trust.
          </p>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "1em",
            }}
          >
            <div>
              <form
                action=""
                style={{ display: "flex", flexFlow: "column nowrap" }}
              >
                <label htmlFor="password">Password</label>
                <input
                  type="password"
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </form>
            </div>
            <div>
              <CopyableCodeblock contents={result} />
              <button
                style={{ float: "right", marginRight: 0, marginTop: "1em" }}
                onClick={() => setIsFirstStep(false)}
              >
                Next
              </button>
            </div>
          </div>
        </>
      ) : (
        <div>
          <p>
            Enter the outputs your contacts have returned to you in the inputs
            below.
          </p>
          <form
            action=""
            style={{ display: "flex", flexFlow: "column nowrap" }}
          >
            {peers.map((peer, i) =>
              selectedPeers[i] ? (
                <div key={peer}>
                  <label htmlFor={`contact-output-${i}`}>{peer} output</label>
                  <textarea
                    id={`contact-output-${i}`}
                    style={{ resize: "none" }}
                    value={contactOutputs[i]}
                    onChange={(e) =>
                      setContactOutputs((outputs) => {
                        let newOutputs = [...outputs];
                        newOutputs[i] = e.target.value;
                        return newOutputs;
                      })
                    }
                  />
                </div>
              ) : null
            )}
            <div>
              <button
                style={{
                  float: "right",
                  marginRight: 0,
                  width: "fit-content",
                }}
                disabled={!contactOutputs.some((output) => output === "")}
                onClick={() => navigate("/")}
              >
                Done
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};

export default Recovery;
