import { ReactElement } from "react";
import JazziconComponent from "./JazziconComponent";

const User = ({ user, actions }: { user: string; actions?: ReactElement }) => (
  <div
    style={{
      display: "flex",
      gap: "1em",
      alignItems: "center",
      maxWidth: "100%",
    }}
  >
    <div style={{ flexBasis: "100px" }}>
      <JazziconComponent user={user} />
    </div>
    <div style={{ minWidth: 0 }}>
      <p
        style={{
          marginBottom: "0.5em",
          whiteSpace: "nowrap",
          textOverflow: "ellipsis",
          overflow: "hidden",
        }}
      >
        <b>{user}</b>
        {!!actions ? actions : null}
      </p>
    </div>
  </div>
);

export default User;
