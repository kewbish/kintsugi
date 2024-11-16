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
  const [username, setUsername] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [recoveryNodes, setRecoveryNodes] = useState([""]);

  const register = () => {
    invoke("local_register", { username, password })
      .then((_) => {
        setIsLoggedIn(true);
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
      <h1 style={{ textAlign: "center" }}>Welcome to Keyntsugi!</h1>
      {stepNum === 0 ? (
        <div>
          <p>Enter the addresses of three or more trusted recovery nodes.</p>
          <div
            style={{
              display: "flex",
              flexDirection: "column",
            }}
          >
            <div>
              {recoveryNodes.map((node, i) => (
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
                      <JazziconComponent user={node} />
                    </div>
                    <input
                      type="text"
                      value={recoveryNodes[i]}
                      onChange={(e) =>
                        setRecoveryNodes((nodes) => {
                          let newNodes = [...nodes];
                          newNodes[i] = e.target.value;
                          return newNodes;
                        })
                      }
                      style={{ minWidth: 0, flexGrow: 1, marginRight: 0 }}
                    />
                    <button
                      onClick={() =>
                        setRecoveryNodes((nodes) =>
                          nodes.filter((_, index) => i != index)
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
                onClick={() => setRecoveryNodes((nodes) => [...nodes, ""])}
              >
                Add recovery node
              </button>
              <button
                title={
                  recoveryNodes.length < 3
                    ? "Add three or more recovery nodes to continue."
                    : new Set(recoveryNodes).size < recoveryNodes.length
                    ? "Recovery nodes must be unique"
                    : undefined
                }
                disabled={
                  recoveryNodes.length < 3 ||
                  new Set(recoveryNodes).size < recoveryNodes.length
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
          <p>Enter a username and a password.</p>
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: "1em",
            }}
          >
            <div>
              <form
                action=""
                style={{ display: "flex", flexFlow: "column nowrap" }}
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
              </form>
            </div>
            <div>
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
