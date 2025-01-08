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
          marginBottom: "0em",
          whiteSpace: "nowrap",
          textOverflow: "ellipsis",
          overflow: "hidden",
        }}
      >
        <b>{user}</b>
      </p>
      {!!actions ? actions : null}
    </div>
  </div>
);

export default User;
