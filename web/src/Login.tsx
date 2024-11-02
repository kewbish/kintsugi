import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import { Link, useNavigate } from "react-router-dom";

function Login() {
  const [peerId, setPeerId] = useState<string>("");
  const [password, setPassword] = useState<string>("");

  useEffect(() => {
    const fetchPeerId = async () => {
      invoke("get_peer_id").then((resp) => setPeerId(resp as string));
    };

    fetchPeerId();
  }, []);

  const navigate = useNavigate();

  const login = () => {
    invoke("check_envelope", { password })
      .then((resp) => {
        toast.success("Successfully logged in!");
        navigate("/");
      })
      .catch((err) => toast.error(err));
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        height: "100%",
        marginTop: "-10em",
      }}
    >
      <h1 style={{ textAlign: "center" }}>Welcome to OP2Paque!</h1>
      <label htmlFor="connection_identifier">Identifier</label>
      <input type="text" id="connection_identifier" value={peerId} disabled />
      <label htmlFor="password">Password</label>
      <input
        type="password"
        id="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <input
        type="submit"
        value="Log in"
        style={{ margin: "1em auto 0" }}
        onClick={() => login()}
      />
      <p style={{ textAlign: "center" }}>
        <Link to="/register">Register</Link>
      </p>
    </div>
  );
}

export default Login;
