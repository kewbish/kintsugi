import toast from "react-hot-toast";

const ClickToCopy = ({ content }: { content: string }) => {
  return (
    <button
      style={{
        padding: "4px",
        position: "absolute",
        top: 10,
        right: 10,
        margin: 0,
      }}
      onClick={() => {
        navigator.clipboard.writeText(content);
        toast("Copied!");
      }}
    >
      <svg
        width="24"
        height="24"
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        fill="currentColor"
        color="#000"
      >
        <path
          fill-rule="evenodd"
          d="M4.75 3A1.75 1.75 0 003 4.75v9.5c0 .966.784 1.75 1.75 1.75h1.5a.75.75 0 000-1.5h-1.5a.25.25 0 01-.25-.25v-9.5a.25.25 0 01.25-.25h9.5a.25.25 0 01.25.25v1.5a.75.75 0 001.5 0v-1.5A1.75 1.75 0 0014.25 3h-9.5zm5 5A1.75 1.75 0 008 9.75v9.5c0 .966.784 1.75 1.75 1.75h9.5A1.75 1.75 0 0021 19.25v-9.5A1.75 1.75 0 0019.25 8h-9.5zM9.5 9.75a.25.25 0 01.25-.25h9.5a.25.25 0 01.25.25v9.5a.25.25 0 01-.25.25h-9.5a.25.25 0 01-.25-.25v-9.5z"
        ></path>
      </svg>
    </button>
  );
};
const CopyableCodeblock = ({ contents }: { contents: string }) => {
  return (
    <pre
      style={{
        width: "100%",
        height: "100%",
        position: "relative",
        marginTop: 0,
      }}
    >
      <ClickToCopy content={contents} />
      <code style={{ height: "100%" }}>{contents}</code>
    </pre>
  );
};

export default CopyableCodeblock;
