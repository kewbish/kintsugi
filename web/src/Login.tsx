import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

function Login() {
  const [peerId, setPeerId] = useState<string>("");

  useEffect(() => {
    const fetchPeerId = async () => {
      invoke("get_peer_id").then((resp) => setPeerId(resp as string));
    };

    fetchPeerId();
  }, []);
  const navigate = useNavigate();
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
      <input type="password" id="password" />
      <input
        type="submit"
        value="Log in"
        style={{ margin: "1em auto 0" }}
        onClick={() => navigate("/")}
      />
    </div>
  );
}

export default Login;
