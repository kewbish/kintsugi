import { DOMElement, useEffect, useRef } from "react";
import jazzicon from "@metamask/jazzicon";

// variant of DJB2
const stringToHash = (str: string) => {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = (hash * 33) ^ str.charCodeAt(i);
  }
  return hash >>> 0;
};

const JazziconComponent = ({ user }: { user: string }) => {
  const iconRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const hash = stringToHash(user);
    const iconElement = jazzicon(100, hash);
    if (iconRef.current) {
      iconRef.current.innerHTML = "";
      iconRef.current.appendChild(iconElement);
    }
  }, [user]);

  return <div ref={iconRef} style={{ width: "100px", height: "100px" }} />;
};

export default JazziconComponent;
