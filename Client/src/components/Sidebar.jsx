import React from "react";
import { useNavigate, useLocation } from "react-router-dom";
import "../css/Sidebar.css";

export default function Sidebar() {
  const navigate = useNavigate();
  const location = useLocation(); // Get current location

  const handleComposeClick = () => {
    navigate("/compose");
  };

  const handleInboxClick = () => {
    navigate("/dashboard");
  };

  return (
    <div className="sidebar-container">
      <nav className="sidebar-nav">
        {/* Dynamically render Compose or Inbox button based on current path */}
        {location.pathname === "/dashboard" ? ( // If on Dashboard page, show Compose button
          <button
            className="sidebar-button compose-button"
            onClick={handleComposeClick}
          >
            <span className="icon">+</span> Compose
          </button>
        ) : (
          // If on any other path (e.g., '/compose'), show Inbox button
          <button className="sidebar-button" onClick={handleInboxClick}>
            <span className="icon">✉️</span> Inbox
          </button>
        )}
      </nav>
    </div>
  );
}
