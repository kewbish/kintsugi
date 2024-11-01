import { Link } from "react-router-dom";

function Home() {
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
      <p>
        You are logged in. See your{" "}
        <Link to={"/contacts"}> recovery contacts</Link> or{" "}
        <Link to="/login">log out</Link>.
      </p>
    </div>
  );
}

export default Home;
