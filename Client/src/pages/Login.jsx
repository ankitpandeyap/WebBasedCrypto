import React, { useState, useContext } from "react";
import { useNavigate } from "react-router-dom";
import { AuthContext } from "../context/AuthContext";

import axiosInstance from "../api/axiosInstance";
import { toast } from "react-toastify";
import LoadingSpinner from "../components/LoadingSpinner";
import "../css/Login.css";
import Header from "../components/Header";

export default function Login() {
  // Step 1: Form fields
  const [usernameOrEmail, setUsernameOrEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const { login } = useContext(AuthContext);
  const navigate = useNavigate();

  // Step 3: Submit handler
  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await axiosInstance.post("/auth/login", {
        usernameOrEmail,
        password,
      });
      /*
            const response = await new Promise((resolve, reject) => {
            setTimeout(async () => {
              try {
                const res = await axiosInstance.post('/auth/login', {
                  username,
                  password,
                });
                resolve(res); // Resolve with the actual response
              } catch (err) {
                reject(err); // Reject with the error from axiosInstance.post
              }
            }, 1000); // Delay of 6 seconds
          });
      */
      // Axios normalizes all header keys to lowercase
      const token =
        response.headers.get("authorization") ||
        response.headers["authorization"];

      if (token) {
        login(token); // store in localStorage + update auth state
        toast.success("Login successful!");
        navigate("/dashboard"); // ✅ Now this should work
      } else {
        toast.error("Login failed: No token received");
      }
    } catch (error) {
      toast.error(
        error.response?.data?.message || "Invalid username or password"
      );
    } finally {
      setLoading(false);
    }
  };

  // Step 6: JSX UI
  return (
    <>
      <Header />
      <div className="min-h-screen flex justify-center items-center bg-gray-100">
        <form onSubmit={handleLoginSubmit} className="space-y-4">
          <h2 className="text-2xl mb-4 font-bold text-center">Login</h2>

          <input
            type="text"
            value={usernameOrEmail}
            onChange={(e) =>setUsernameOrEmail(e.target.value)}
            placeholder="Username Or Email"
            required
            className="w-full border p-2 mb-4 rounded"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
            required
            className="w-full border p-2 mb-4 rounded"
          />
          {loading ? (
            <LoadingSpinner />
          ) : (
            <button type="submit" className="btn">
              Login
            </button>
          )}
        </form>
      </div>
    </>
  );
}
