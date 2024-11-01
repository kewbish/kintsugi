import { ReactElement } from "react";
import JazziconComponent from "./JazziconComponent";

const User = ({ user, actions }: { user: string; actions?: ReactElement }) => (
  <div
    style={{
      display: "flex",
      gap: "1em",
      alignItems: "center",
    }}
  >
    <div style={{ flexBasis: "100px" }}>
      <JazziconComponent user={user} />
    </div>
    <div>
      <p style={{ marginBottom: "0.5em" }}>
        <b>{user}</b>
        {!!actions ? actions : null}
      </p>
    </div>
  </div>
);

export default User;
