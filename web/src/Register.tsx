import { invoke } from "@tauri-apps/api/core";
import { useContext, useEffect, useState } from "react";
import toast from "react-hot-toast";
import { Link, useNavigate } from "react-router-dom";
import { useDebounce } from "use-debounce";
import { AuthContext } from "./components/AuthContext";
import CopyableCodeblock from "./components/CopyableCodeblock";
import JazziconComponent from "./components/JazziconComponent";

function Register() {
  const navigate = useNavigate();

  const [stepNum, setStepNum] = useState(0);
  const [password, setPassword] = useState<string>("");
  const [debouncedPassword] = useDebounce(password, 1000);
  const [result, setResult] = useState("");
  const [recoveryContacts, setRecoveryContacts] = useState([""]);
  const [contactOutputs, setContactOutputs] = useState<string[]>([]);
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

  useEffect(() => {
    if (stepNum === 2 && contactOutputs.length === 0) {
      setContactOutputs(new Array(recoveryContacts.length).fill(""));
    }
  }, [stepNum]);

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
      {stepNum === 0 ? (
        <div>
          <p>
            Enter the addresses of three or more trusted recovery contacts who
            you have another secure channel of communication with.
          </p>
          <div
            style={{
              display: "flex",
              flexDirection: "column",
            }}
          >
            <div>
              {recoveryContacts.map((contact, i) => (
                <div
                  key={i}
                  style={{
                    border: "2px solid var(--main)",
                    padding: "1em",
                    borderRadius: "1em",
                    marginBottom: "1em",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      gap: "1em",
                      alignItems: "center",
                      maxWidth: "100%",
                      width: "100%",
                    }}
                  >
                    <div style={{ flexBasis: "100px" }}>
                      <JazziconComponent user={contact} />
                    </div>
                    <input
                      type="text"
                      value={recoveryContacts[i]}
                      onChange={(e) =>
                        setRecoveryContacts((contacts) => {
                          let newContacts = [...contacts];
                          newContacts[i] = e.target.value;
                          return newContacts;
                        })
                      }
                      style={{ minWidth: 0, flexGrow: 1, marginRight: 0 }}
                    />
                    <button
                      onClick={() =>
                        setRecoveryContacts((contacts) =>
                          contacts.filter((_, index) => i != index)
                        )
                      }
                      style={{ paddingRight: "1em", paddingLeft: "1em" }}
                    >
                      X
                    </button>
                  </div>
                </div>
              ))}
            </div>
            <div
              style={{
                display: "flex",
                justifyContent: "flex-end",
              }}
            >
              <button
                onClick={() =>
                  setRecoveryContacts((contacts) => [...contacts, ""])
                }
              >
                Add recovery contact
              </button>
              <button
                title={
                  recoveryContacts.length < 3
                    ? "Add three or more recovery contacts to continue."
                    : new Set(recoveryContacts).size < recoveryContacts.length
                    ? "Recovery contacts must be unique"
                    : undefined
                }
                disabled={
                  recoveryContacts.length < 3 ||
                  new Set(recoveryContacts).size < recoveryContacts.length
                }
                onClick={() => setStepNum(1)}
              >
                Next
              </button>
            </div>
          </div>
        </div>
      ) : null}
      {stepNum === 1 ? (
        <>
          <a style={{ cursor: "pointer" }} onClick={() => setStepNum(0)}>
            &lt; back
          </a>
          <p>
            Enter your password, then send this output to your recovery contacts
            via email, messenger, or another communication medium you trust.
          </p>
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
                onClick={() => setStepNum(2)}
              >
                Next
              </button>
            </div>
          </div>
        </>
      ) : null}
      {stepNum === 2 ? (
        <>
          <a style={{ cursor: "pointer" }} onClick={() => setStepNum(1)}>
            &lt; back
          </a>
          <p>
            Enter the outputs your contacts have returned to you in the inputs
            below. Send each of them the result on the right, then click
            'Register' to proceed.
          </p>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "1em",
            }}
          >
            <div>
              {recoveryContacts.map((contact, i) => (
                <div
                  key={contact}
                  style={{ display: "flex", flexFlow: "column nowrap" }}
                >
                  <label htmlFor="contact-output">{contact} output</label>
                  <textarea
                    id="contact-output"
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
              ))}
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
        </>
      ) : null}
      <p style={{ textAlign: "center" }}>
        <Link to="/login">Login</Link>
      </p>
    </div>
  );
}

export default Register;
