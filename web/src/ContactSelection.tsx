import { Link } from "react-router-dom";
import User from "./components/User";

const ContactSelection = () => {
  const USERS = [
    "/dnsaddr/bootstrap.libp2p.io/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
  ];

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        height: "100%",
        marginTop: "-5em",
      }}
    >
      <Link to="/">&lt; back</Link>
      <h1>Recovery contacts</h1>
      {USERS.map((user, i) => (
        <div>
          <User
            user={user}
            actions={
              <>
                <button>Remove contact</button>
                <button>Send password check reminder</button>
              </>
            }
          />
          {i != USERS.length - 1 ? <hr style={{ marginTop: "1em" }} /> : null}
        </div>
      ))}
    </div>
  );
};

export default ContactSelection;
