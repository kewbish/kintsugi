import { invoke } from "@tauri-apps/api/core";
import { useContext, useEffect, useState } from "react";
import toast from "react-hot-toast";
import { Link, useNavigate } from "react-router-dom";
import { useDebounce } from "use-debounce";
import { AuthContext } from "./components/AuthContext";
import CopyableCodeblock from "./components/CopyableCodeblock";

function Register() {
  const navigate = useNavigate();

  const [isFirstStep, setIsFirstStep] = useState(true);
  const [password, setPassword] = useState<string>("");
  const [debouncedPassword] = useDebounce(password, 1000);
  const [result, setResult] = useState("");
  const [contactOutput, setContactOutput] = useState("");
  const [debouncedContactOutput] = useDebounce(password, 1000);
  const [secondResult, setSecondResult] = useState("");

  useEffect(() => {
    if (!debouncedPassword) {
      return;
    }
    invoke("local_register_start", { password })
      .then((resp) => {
        setResult(resp as string);
      })
      .catch((err) => toast.error(err));
  }, [debouncedPassword]);

  useEffect(() => {
    if (!debouncedContactOutput) {
      return;
    }
    invoke("local_register_finish", {
      password,
      peerResp: debouncedContactOutput,
    })
      .then((resp) => {
        setSecondResult(resp as string);
      })
      .catch((err) => toast.error(err));
  }, [debouncedContactOutput]);

  const register = () => {
    invoke("local_register", { password })
      .then((_) => {
        toast.success("Successfully registered!");
        navigate("/");
      })
      .catch((err) => {
        toast.error(err);
      });
  };

  const { isLoggedIn, setIsLoggedIn } = useContext(AuthContext);

  if (isLoggedIn) {
    toast("User is already authenticated!");
    navigate("/");
  }

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
      <h1 style={{ textAlign: "center" }}>Welcome to OP2Paque!</h1>
      <p>
        Send this output to your recovery contact via email, messenger, or
        another communication medium you trust.
      </p>
      {isFirstStep ? (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gridAutoRows: "auto",
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
              style={{ float: "right", marginRight: 0 }}
              onClick={() => setIsFirstStep(false)}
            >
              Next
            </button>
          </div>
        </div>
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "1em",
          }}
        >
          <div style={{ display: "flex", flexFlow: "column nowrap" }}>
            <label htmlFor="contact-output">Contact output</label>
            <textarea
              id="contact-output"
              style={{ resize: "none" }}
              value={contactOutput}
              onChange={(e) => setContactOutput(e.target.value)}
            />
          </div>
          <div>
            <CopyableCodeblock contents={secondResult} />
            <button
              style={{ float: "right", marginRight: 0 }}
              onClick={() => register()}
            >
              Register
            </button>
          </div>
        </div>
      )}
      <p style={{ textAlign: "center" }}>
        <Link to="/login">Login</Link>
      </p>
    </div>
  );
}

export default Register;
