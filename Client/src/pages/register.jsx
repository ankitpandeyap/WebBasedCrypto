import React, { useState, useEffect } from "react";
import axiosInstance from "../api/axiosInstance";
import "../css/Register.css";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";

// Import CSS and component for LoadingSpinner
// Note: It's good practice to keep component-specific styles with the component
const LoadingSpinner = ({ className }) => {
  return (
    <div className={className}>
      <div className="spinner"></div>
      <p className="loading-text">Loading, please wait...</p>
    </div>
  );
};
// LoadingSpinner CSS (Overriding for Register Page)
const loadingSpinnerCSS = `
.button-spinner {
  display: flex;
  flex-direction: column; /* Stack items vertically */
  align-items: center; /* Center horizontally */
  justify-content: center; /* Center vertically */
  height: 2.5rem;
  width: 100%;
}

.spinner {
  width: 2rem;
  height: 2rem;
  border: 0.3em solid rgba(0, 0, 0, 0.2);
  border-top: 0.3em solid #007bff;
  border-radius: 50%;
  animation: rotate 1.2s linear infinite;
  margin-bottom: 0.5rem; /* Add space between spinner and text */
}

.loading-text {
  font-size: 0.8rem;
  color: #555;
  font-style: normal; /* Changed to normal */
  font-weight: 400;  /*make the font normal weight */
}

@keyframes rotate {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
}
`;

export default function Register() {
  const [email, setEmail] = useState("");
  const [userName, setUserName] = useState(""); // Corrected to userName
  const [password, setPassword] = useState("");
  const [passkey, setPasskey] = useState("");
  const [otp, setOtp] = useState("");
  const [step, setStep] = useState(1);
  const [name, setName] = useState(""); // Corrected to name
  const [role, setRole] = useState("USER");
  const navigate = useNavigate();

  const [sendingOtp, setSendingOtp] = useState(false);
  const [verifyingOtp, setVerifyingOtp] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [otpVerified, setOtpVerified] = useState(false);

  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = loadingSpinnerCSS; // Here's where loadingSpinnerCSS is used
    document.head.appendChild(style);

    // Cleanup function: remove the style tag when the component unmounts
    return () => {
      document.head.removeChild(style);
    };
  }, []); // Empty dependency array ensures this runs only once on mount and once on unmount

  const handleSendOtp = async (e) => {
    e.preventDefault();
    setSendingOtp(true);
    try {
      const res = await axiosInstance.post(
        `/auth/otp/request?email=${encodeURIComponent(email)}`
      );
      toast.success(res.data); // Backend sends "OTP sent to email@example.com"
      setStep(2);
    } catch (err) {
      toast.error(err.response?.data || "Failed to send OTP"); // Error response might be directly the message
    } finally {
      setSendingOtp(false); // Stop loading
    }
  };

  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    setVerifyingOtp(true);
    try {
      const res = await axiosInstance.post(
        `/auth/otp/verify?email=${encodeURIComponent(
          email
        )}&otp=${encodeURIComponent(otp)}`
      );
      toast.success(res.data);
      if (res.data.trim() === "OTP verified") {
        setOtpVerified(true);
        setStep(3);
      }
    } catch (err) {
      // The backend now sends the specific error message, e.g., "Invalid OTP." or "Too many failed attempts."
      toast.error(err.response?.data || "OTP verification failed");
    } finally {
      setVerifyingOtp(false); // Stop loading
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!otpVerified) {
      toast.error("Please verify OTP first.");
      return;
    }
    const passkeyInt = parseInt(passkey, 10);
    if (isNaN(passkeyInt)) {
      toast.error("Passkey must be a number.");
      return;
    }
    setRegistering(true);
    try {
      const res = await axiosInstance.post("/auth/register", {
        email: email,
        userName: userName, // Map 'username' state to 'userName' DTO field
        password: password,
        passkey: passkeyInt, // Include the passkey
        role: role, // Include the selected role
        name: name,
      });
      toast.success(res.data); // Backend sends "User registered successfully!"
      navigate("/login");
    } catch (err) {
      // Backend sends specific error messages from AuthController, e.g., "Email has not been verified..."
      // or "Email already registered!"
      toast.error(err.response?.data || "Registration failed");
    } finally {
      setRegistering(false); // Stop loading for registration
    }
  };

  return (
    <div className="register-container">
      <div className="register-card"> {/* MINOR: Clarified use of .register-card */}
        <h2 className="register-title"> {/* MINOR: Clarified use of .register-title */}
          {step === 1 && "Step 1: Send OTP"}
          {step === 2 && "Step 2: Verify OTP"}
          {step === 3 && "Step 3: Complete Registration"}
        </h2>

        {step === 1 && (
          <form onSubmit={handleSendOtp} className="register-form">
            <input
              type="email"
              placeholder="Enter your email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            {sendingOtp ? (
              <LoadingSpinner className="button-spinner" />
            ) : (
              <button
                type="submit"
                className="btn-primary otp-button"
                disabled={sendingOtp}
              >
                Send OTP
              </button>
            )}
          </form>
        )}

        {step === 2 && (
          <form onSubmit={handleVerifyOtp} className="register-form">
            <input
              type="text"
              placeholder="Enter OTP"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              required
            />
            {verifyingOtp ? (
              <LoadingSpinner className="button-spinner" />
            ) : (
              <button
                type="submit"
                className="btn-primary otp-button"
                disabled={verifyingOtp}
              >
                Verify OTP
              </button>
            )}
          </form>
        )}

        {step === 3 && otpVerified && (
          <form onSubmit={handleRegister} className="register-form">
            <input
              type="text"
              placeholder="Username"
              value={userName}
              onChange={(e) => setUserName(e.target.value)}
              required
            />
            <input
              type="text"
              placeholder="Full Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <input
              type="number"
              placeholder="Passkey (numeric code)"
              value={passkey}
              onChange={(e) => setPasskey(e.target.value)}
              required
            />
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="register-dropdown"
            >
              <option value="USER">User</option>
              <option value="ADMIN">Admin</option>
            </select>
            {registering ? (
              <LoadingSpinner className="button-spinner" />
            ) : (
              <button
                type="submit"
                className="btn-primary complete-register"
                disabled={registering}
              >
                Complete Registration
              </button>
            )}
          </form>
        )}
      </div>
    </div>
  );
}
