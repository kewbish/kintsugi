import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import Home from "./Home";
import Login from "./Login";
import ContactSelection from "./ContactSelection";
import Recovery from "./Recovery";
import { Toaster } from "react-hot-toast";
import "react-loading-skeleton/dist/skeleton.css";
import Register from "./Register";
import { AuthProvider } from "./components/AuthContext";
import RequiresAuth from "./components/RequiresAuth";

const router = createBrowserRouter([
  {
    path: "/",
    element: (
      <RequiresAuth>
        <Home />
      </RequiresAuth>
    ),
  },
  {
    path: "/login",
    element: <Login />,
  },
  {
    path: "/register",
    element: <Register />,
  },
  {
    path: "/recovery",
    element: <Recovery />,
  },
  {
    path: "/contacts",
    element: (
      <RequiresAuth>
        <ContactSelection />
      </RequiresAuth>
    ),
  },
]);

createRoot(document.getElementById("root")!).render(
  <>
    <Toaster />
    <AuthProvider>
      <RouterProvider router={router} />
    </AuthProvider>
  </>
);
