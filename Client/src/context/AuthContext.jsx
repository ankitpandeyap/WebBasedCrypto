// src/context/AuthContext.js
import React, { createContext, useState, useEffect } from "react";
import axiosInstance from "../api/axiosInstance"; // Make sure this path is correct

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  // State variables for authentication status, access token, and loading status
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [accessToken, setAccessToken] = useState(null);
  const [loadingAuth, setLoadingAuth] = useState(true); // True initially, until check completes

  // Effect to perform initial authentication check when component mounts
  useEffect(() => {
    const checkAuthStatus = async () => {
      const storedToken = localStorage.getItem("accessToken");

      if (storedToken) {
        try {
          // Attempt to validate the token using your /api/auth/validate endpoint
          // axiosInstance interceptors will automatically add the Authorization header
          // and handle refresh logic if configured.
          await axiosInstance.get("/api/auth/validate");

          // If the validation call succeeds, set authenticated state
          setIsAuthenticated(true);
          setAccessToken(storedToken); // Use the stored token
        } catch (error) {
          // If validation fails (e.g., 401/403 from backend), token is invalid/expired
          console.error("Stored token is invalid or expired via /api/auth/validate:", error);
          localStorage.removeItem("accessToken"); // Remove invalid token
          setIsAuthenticated(false);
          setAccessToken(null);
          // axiosInstance interceptor should handle clearing default header if token is invalid
        }
      }
      // Authentication check is complete, regardless of outcome
      setLoadingAuth(false);
    };

    checkAuthStatus();
  }, []); // Empty dependency array means this effect runs only once on mount

  // Function to handle user login
  const login = (token) => {
    // Extract token value if it comes with "Bearer " prefix
    const tokenValue = token.startsWith("Bearer ") ? token.split(" ")[1] : token;
    localStorage.setItem("accessToken", tokenValue); // Store in local storage
    setIsAuthenticated(true); // Update authentication status
    setAccessToken(tokenValue); // Store the token in state
    // axiosInstance.defaults.headers.common['Authorization'] is set by axiosInstance's interceptor on subsequent calls
  };

  // Function to handle user logout
  const logout = () => {
    try {
      localStorage.removeItem("accessToken"); // Remove token from local storage
      setIsAuthenticated(false); // Update authentication status
      setAccessToken(null); // Clear token from state
      // axiosInstance.defaults.headers.common['Authorization'] is cleared by axiosInstance's interceptor on 401
    } catch (error) {
      console.error("Logout error:", error);
    }
  };

  // Provide the state variables and functions to components consuming this context
  return (
    <AuthContext.Provider value={{ isAuthenticated, login, logout, accessToken, loadingAuth }}>
      {/* Conditionally render children or a loading indicator based on loadingAuth state */}
      {loadingAuth ? (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', fontSize: '1.2em' }}>
          Loading application...
        </div>
      ) : (
        children
      )}
    </AuthContext.Provider>
  );
};