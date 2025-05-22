import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import axiosInstance from "../api/axiosInstance";
import Header from "../components/Header"; // Include Header for consistent layout
import Sidebar from "../components/Sidebar"; // IMPORT Sidebar
import "../css/ComposeMessage.css"; // Link to its dedicated CSS

export default function ComposeMessage() {
  const [recipient, setRecipient] = useState("");
  const [messageContent, setMessageContent] = useState("");
  const [encryptionType, setEncryptionType] = useState("AES"); // Default to AES
  const [passkey, setPasskey] = useState("");
  const [loading, setLoading] = useState(false);
  const [availableUsers, setAvailableUsers] = useState([]); // For recipient suggestions/dropdown
  const navigate = useNavigate();

  // Fetch list of users for recipient selection (optional, but good UX)
  useEffect(() => {
    const fetchUsers = async () => {
      try {
        // NOTE: This API endpoint /users/all needs to be created on the backend.
        // If it doesn't exist, this fetch will fail.
        const response = await axiosInstance.get("/users/all");
        setAvailableUsers(response.data);
      } catch (error) {
        console.error("Failed to fetch users:", error);
        // Do not block the compose functionality if users can be typed manually
        // toast.error('Failed to load users for recipient list.'); // Optional: show error to user
      }
    };
    fetchUsers();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axiosInstance.post("/messages/send", {
        recipientUsername: recipient,
        content: messageContent,
        encryptionType: encryptionType,
        passkey: passkey,
      });
      toast.success(response.data || "Message sent successfully!");
      navigate("/dashboard");
    } catch (error) {
      console.error("Failed to send message:", error);
      toast.error(
        "Failed to send message: " + (error.response?.data || error.message)
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Header /> {/* Header remains at the top */}
      {/* CORRECTED: main-dashboard-layout to include Sidebar */}
      <div className="main-dashboard-layout">
        <Sidebar /> {/* Sidebar on the left */}

        {/* Existing compose-container now acts as the main content area for Compose */}
        <div className="compose-container">
          <div className="compose-box">
            <h1 className="compose-title">Compose New Message</h1>
            <form onSubmit={handleSubmit} className="compose-form">
              <div className="form-group">
                <label htmlFor="recipient" className="form-label">
                  To:
                </label>
                <input
                  id="recipient"
                  type="text"
                  value={recipient}
                  onChange={(e) => setRecipient(e.target.value)}
                  placeholder="Recipient username or Email NOTE:PRESENT IN OUR SYSTEM"
                  required
                  className="form-input"
                  list="available-users" // Use datalist for suggestions if availableUsers populated
                />
                {availableUsers.length > 0 && (
                  <datalist id="available-users">
                    {availableUsers.map((user) => (
                      <option key={user.id} value={user.username} />
                    ))}
                  </datalist>
                )}
              </div>

              <div className="form-group">
                <label htmlFor="messageContent" className="form-label">
                  Message:
                </label>
                <textarea
                  id="messageContent"
                  value={messageContent}
                  onChange={(e) => setMessageContent(e.target.value)}
                  placeholder="Your message content"
                  rows="8"
                  required
                  className="form-textarea"
                ></textarea>
              </div>

              <div className="form-group">
                <label htmlFor="encryptionType" className="form-label">
                  Encryption Algorithm:
                </label>
                <select
                  id="encryptionType"
                  value={encryptionType}
                  onChange={(e) => setEncryptionType(e.target.value)}
                  className="form-select"
                >
                  <option value="AES">AES</option>
                  <option value="CAESAR">Caesar</option>
                  <option value="MONO_ALPHABETIC_CIPHER">Monoalphabetic</option>
                  <option value="CUSTOM">Custom</option>
                </select>
                {(encryptionType === "CAESAR" ||
                  encryptionType === "MONO_ALPHABETIC_CIPHER" ||
                  encryptionType === "CUSTOM") && (
                  <p className="algorithm-warning">
                    Warning: Caesar, Monoalphabetic, and Custom ciphers are not
                    secure for sensitive data.
                  </p>
                )}
              </div>

              <div className="form-group">
                <label htmlFor="passkey" className="form-label">
                  Passkey:
                </label>
                <input
                  id="passkey"
                  type="password"
                  value={passkey}
                  onChange={(e) => setPasskey(e.target.value)}
                  placeholder="Passkey for encryption/decryption"
                  required
                  className="form-input"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="compose-submit-btn"
              >
                {loading ? "Sending..." : "Send Message"}
              </button>
            </form>
          </div>
        </div>
      </div>
    </>
  );
}
