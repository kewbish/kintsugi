import { invoke } from "@tauri-apps/api/core";
import { useContext, useEffect, useState } from "react";
import toast from "react-hot-toast";
import { Link, useNavigate } from "react-router-dom";
import { AuthContext } from "./components/AuthContext";

function Register() {
  const [password, setPassword] = useState<string>("");
  const navigate = useNavigate();

  const register = () => {
    invoke("save_envelope", { password })
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
        marginTop: "-10em",
      }}
    >
      <h1 style={{ textAlign: "center" }}>Welcome to OP2Paque!</h1>
      <label htmlFor="password">Password</label>
      <input
        type="password"
        id="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <input
        type="submit"
        value="Register"
        style={{ margin: "1em auto 0" }}
        onClick={() => register()}
      />
      <p style={{ textAlign: "center" }}>
        <Link to="/login">Login</Link>
      </p>
    </div>
  );
}

export default Register;
