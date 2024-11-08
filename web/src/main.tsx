import { StrictMode } from "react";
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
import PeerRecovery from "./PeerRecovery";
import PeerRegistration from "./PeerRegistration";

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
    path: "/contacts",
    element: <ContactSelection />,
  },
  {
    path: "/recovery/contacts",
    element: (
      // TODO - readd auth
      <Recovery />
    ),
  },
  {
    path: "/recovery/peers",
    element: (
      // TODO - readd auth
      <PeerRecovery />
    ),
  },
  {
    path: "/register/peers",
    element: (
      // TODO - readd auth
      <PeerRegistration />
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
