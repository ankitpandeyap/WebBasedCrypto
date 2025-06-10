import React, { useContext } from "react"; // Import useContext
import { Routes, Route, Navigate } from "react-router-dom";
import { useLocation } from "react-router-dom";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

// Import your components
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Register from "./pages/Register";
import ProtectedRoute from "./components/ProtectedRoute";
import Footer from "./components/Footer";
import SentMessages from './pages/SentMessages';
import ComposeMessage from "./pages/ComposeMessage";
import ProfilePage from "./pages/ProfilePage";
import ForgotPasswordPage from "./pages/ForgotPasswordPage";
import ResetPasswordPage from "./pages/ResetPasswordPage";

// Import AuthContext
import { AuthContext } from "./context/AuthContext";

export default function App() {
  const location = useLocation();
  // Get isAuthenticated and loadingAuth from AuthContext
  const { isAuthenticated, loadingAuth } = useContext(AuthContext);

  // If authentication status is still loading, you might want to show a loading screen
  // or simply let the AuthProvider handle it as you've already done there.
  // For routing, it's safer to wait until loadingAuth is false.
  if (loadingAuth) {
    return null; // Or a simple loading spinner/indicator if you want to explicitly show something here
  }

  return (
    <>
      <Routes>
        <Route path="/" element={<Navigate to="/login" />} />

        {/* Conditional rendering for Login and Register */}
        <Route
          path="/login"
          element={isAuthenticated ? <Navigate to="/dashboard" /> : <Login />}
        />
        <Route
          path="/register"
          element={isAuthenticated ? <Navigate to="/dashboard" /> : <Register />}
        />

        {/* Routes that don't require authentication check for redirection (password reset) */}
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />

        {/* Protected routes */}
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
          path="/profile"
          element={
            <ProtectedRoute>
              <ProfilePage />
            </ProtectedRoute>
          }
        />
      </Routes>
      {/* Conditionally render Footer only on the login page */}
      {location.pathname === "/login" && <Footer />}
      <ToastContainer position="top-center" autoClose={1000} />
    </>
  );
}