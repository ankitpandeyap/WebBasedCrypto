import { Routes, Route, Navigate } from "react-router-dom";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Register from "./pages/Register";
import ProtectedRoute from "./components/ProtectedRoute";
import { useLocation } from "react-router-dom";
import Footer from "./components/Footer";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import SentMessages from './pages/SentMessages';
import ComposeMessage from "./pages/ComposeMessage";
import ProfilePage from "./pages/ProfilePage"; // <--- NEW IMPORT

export default function App() {
  const location = useLocation(); // 🔍 Detect current route

  return (
    <>
      <Routes>
        <Route path="/" element={<Navigate to="/login" />} />
        <Route path="/register" element={<Register />} />
        <Route path="/login" element={<Login />} />

        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />
        <Route
          path="/compose"
          element={
            <ProtectedRoute>
              <ComposeMessage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/sent"
          element={
            <ProtectedRoute>
              <SentMessages />
            </ProtectedRoute>
          }
        />
        <Route
          path="/profile" // <--- NEW ROUTE PATH
          element={
            <ProtectedRoute>
              <ProfilePage /> {/* <--- Renders your new ProfilePage component */}
            </ProtectedRoute>
          }
        />
      </Routes>
      {location.pathname === "/login" && <Footer />}
      <ToastContainer position="top-center" autoClose={1000} />
    </>
  );
}