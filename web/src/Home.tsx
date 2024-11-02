import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import { Link } from "react-router-dom";

function Home() {
  const [notepad, setNotepad] = useState("");

  useEffect(() => {
    invoke("read_notepad")
      .then((resp) => {
        setNotepad(resp as string);
      })
      .catch((err) => toast.error(err));
  }, []);

  const saveNotepad = async () => {
    await invoke("save_notepad", { notepad }).catch((err) =>
      toast.error(err.toString())
    );
  };

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
      <h2>Encrypted Notepad</h2>
      <textarea
        id="notepad"
        name="notepad"
        cols={30}
        rows={10}
        value={notepad}
        onChange={(e) => setNotepad(e.target.value)}
      ></textarea>
      <button onClick={saveNotepad}>Save</button>
    </div>
  );
}

export default Home;
