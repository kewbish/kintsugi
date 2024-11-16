import { invoke } from "@tauri-apps/api/core";
import { useContext, useEffect, useState } from "react";
import toast from "react-hot-toast";
import { Link, useNavigate } from "react-router-dom";
import { AuthContext } from "./components/AuthContext";

function Login() {
  const [username, setUsername] = useState<string>("");
  const [password, setPassword] = useState<string>("");

  const navigate = useNavigate();

  const login = () => {
    invoke("local_login", { username, password })
      .then((resp) => {
        setIsLoggedIn(true);
        toast.success("Successfully logged in!");
        navigate("/");
      })
      .catch((err) => toast.error(err));
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
        marginTop: "-10em",
      }}
    >
      <h1 style={{ textAlign: "center" }}>Welcome to Keyntsugi!</h1>
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
