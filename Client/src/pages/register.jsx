import React, { useState } from 'react';
import axiosInstance from '../api/axiosInstance';
import '../css/Register.css';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';

export default function Register() {
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState(''); // Corresponds to userName in backend DTO
  const [password, setPassword] = useState('');
  const [passkey, setPasskey] = useState(''); // New state for passkey
  const [otp, setOtp] = useState('');
  const [step, setStep] = useState(1);

  const [otpVerified, setOtpVerified] = useState(false);
  const [role, setRole] = useState('USER'); // Changed default from 'CONSUMER' to 'USER' based on backend enum
  const navigate = useNavigate();

  const handleSendOtp = async (e) => {
    e.preventDefault();
    try {
      const res = await axiosInstance.post(`/auth/otp/request?email=${encodeURIComponent(email)}`);
      toast.success(res.data); // Backend sends "OTP sent to email@example.com"
      setStep(2);
    } catch (err) {
      toast.error(err.response?.data || 'Failed to send OTP'); // Error response might be directly the message
    }
  };

  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    try {
      const res = await axiosInstance.post(
        `/auth/otp/verify?email=${encodeURIComponent(email)}&otp=${encodeURIComponent(otp)}`
      );
      toast.success(res.data);
      if (res.data.trim() === 'OTP verified') {
        setOtpVerified(true);
        setStep(3);
      }
    } catch (err) {
      // The backend now sends the specific error message, e.g., "Invalid OTP." or "Too many failed attempts."
      toast.error(err.response?.data || 'OTP verification failed');
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!otpVerified) {
      toast.error('Please verify OTP first.');
      return;
    }
    try {
      const res = await axiosInstance.post('/auth/register', {
        email: email,
        userName: username, // Map 'username' state to 'userName' DTO field
        password: password,
        passkey: passkey, // Include the passkey
        role: role, // Include the selected role
      });
      toast.success(res.data); // Backend sends "User registered successfully!"
      navigate('/login');
    } catch (err) {
      // Backend sends specific error messages from AuthController, e.g., "Email has not been verified..."
      // or "Email already registered!"
      toast.error(err.response?.data || 'Registration failed');
    }
  };

  return (
    <div className="register-container">
      <div className="register-card"> {/* Changed from register-box to register-card to match CSS */}
        <h2 className="register-title">
          {step === 1 && 'Step 1: Send OTP'}
          {step === 2 && 'Step 2: Verify OTP'}
          {step === 3 && 'Step 3: Complete Registration'}
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
            <button
              type="submit"
              className="btn-primary otp-button"
            >
              Send OTP
            </button>
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
            <button
              type="submit"
              className="btn-primary otp-button"
            >
              Verify OTP
            </button>
          </form>
        )}

        {step === 3 && otpVerified && (
          <form onSubmit={handleRegister} className="register-form">
            {/* Email input is not needed here as it's already collected and verified */}
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            {/* New Passkey Input */}
            <input
              type="password" // Use type="password" for sensitive passkey input
              placeholder="Passkey (for secure access)"
              value={passkey}
              onChange={(e) => setPasskey(e.target.value)}
              required
            />
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="register-dropdown"
            >
              <option value="USER">User</option> {/* Changed 'CONSUMER' to 'USER' */}
              <option value="ADMIN">Admin</option>
            </select>
            <button
              type="submit"
              className="btn-primary complete-register"
            >
              Complete Registration
            </button>
          </form>
        )}
      </div>
    </div>
  );
}