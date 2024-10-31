import { useState } from "react";
import { useNavigate } from "react-router-dom";

function Login() {
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
      <div
        style={{
          width: "fit-content",
          margin: "0 auto",
        }}
      >
        {/* TODO - have this be auto-fetched by JS → RS */}
        <label htmlFor="connection_identifier">Identifier</label>
        <input type="text" id="connection_identifier" />
        <label htmlFor="password">Password</label>
        <input type="password" id="password" />
        <input
          type="submit"
          value="Log in"
          style={{ margin: "1em auto 0" }}
          onClick={() => navigate("/")}
        />
      </div>
    </div>
  );
}

export default Login;
