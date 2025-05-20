import React, { useEffect, useState } from 'react';
import { useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import '../css/Dashboard.css'

export default function Dashboard() {
  const [token, setToken] = useState('');

  useEffect(() => {
    // Read token from localStorage
    const savedToken = localStorage.getItem('accessToken');
    setToken(savedToken || 'No token found');
  }, []);

  const { logout } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    toast.success('Logged out successfully');
    navigate('/login');
  };


  return (
    <div className="dashboard-container">
      <div className="dashboard-box">

        <h1 className="text-3xl font-bold mb-4">Dashboard</h1>
        <p className="text-lg text-gray-700 mb-4">Welcome! 🎉</p>
        <p className="text-sm break-words text-gray-500">
          <strong>Access Token:</strong><br /> {token}
        </p>
        <button className="logout-btn" onClick={handleLogout}>
      Logout
    </button>
      </div>
    </div>

  );
}
