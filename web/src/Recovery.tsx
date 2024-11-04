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

  const { peer } = useParams();
  const [isFirstStep, setIsFirstStep] = useState(true);
  const [password, setPassword] = useState("");
  const [debouncedPassword] = useDebounce(password, 1000);
  const [result, setResult] = useState("");
  const [contactOutput, setContactOutput] = useState("");
  const [debouncedContactOutput] = useDebounce(password, 1000);
  const [secondResult, setSecondResult] = useState("");

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
    if (!debouncedContactOutput) {
      return;
    }
    invoke("local_login_finish", { password, peerResp: debouncedContactOutput })
      .then((resp) => {
        setSecondResult(resp as string);
      })
      .catch((err) => toast.error(err));
  }, [debouncedContactOutput]);

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
      <h1>Request recovery from peer</h1>
      <h2>Selected Peer</h2>
      {peer != undefined ? (
        <div
          style={{
            border: "2px solid var(--main)",
            borderRadius: "1em",
            padding: "1em",
          }}
        >
          <User user={peer} />
        </div>
      ) : (
        <Skeleton
          height={136}
          baseColor={"var(--background)"}
          highlightColor={"var(--main-light)"}
          borderRadius={"1em"}
        />
      )}
      <h2>Calculator</h2>
      <p>
        Send this output to your recovery contact via email, messenger, or
        another communication medium you trust.
      </p>
      {isFirstStep ? (
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
      ) : (
        <div>
          <form
            action=""
            style={{ display: "flex", flexFlow: "column nowrap" }}
          >
            <label htmlFor="contact-output">Contact output</label>
            <textarea
              id="contact-output"
              style={{ resize: "none" }}
              value={contactOutput}
              onChange={(e) => setContactOutput(e.target.value)}
            />
            <div>
              <button
                style={{
                  float: "right",
                  marginRight: 0,
                  width: "fit-content",
                }}
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
