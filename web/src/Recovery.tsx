import Skeleton from "react-loading-skeleton";
import { Link, useParams } from "react-router-dom";
import CopyableCodeblock from "./components/CopyableCodeblock";
import User from "./components/User";

const Recovery = () => {
  const { peer } = useParams();
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
            <input type="password" id="password" />
          </form>
        </div>
        <div>
          <CopyableCodeblock contents={"testtesttest"} />
        </div>
      </div>
    </div>
  );
};

export default Recovery;
