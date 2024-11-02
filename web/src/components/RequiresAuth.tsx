import { ReactElement, ReactNode, useContext, useEffect } from "react";
import toast from "react-hot-toast";
import { useNavigate } from "react-router-dom";
import { AuthContext } from "./AuthContext";

const RequiresAuth = ({ children }: { children: ReactElement }) => {
  const { isLoggedIn } = useContext(AuthContext);
  const navigate = useNavigate();

  useEffect(() => {
    if (!isLoggedIn) {
      toast.error("User is not authenticated.");
      navigate("/login");
    }
  }, [isLoggedIn]);

  return children;
};

export default RequiresAuth;
