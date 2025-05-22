import React, { useEffect, useState } from "react";

import { toast } from "react-toastify";
import axiosInstance from "../api/axiosInstance";
import Header from "../components/Header";
import "../css/Dashboard.css";
import Sidebar from "../components/Sidebar";
import DecryptModal from "../components/DecryptModal";

export default function Dashboard() {
  const [messages, setMessages] = useState([]);
  const [loadingMessages, setLoadingMessages] = useState(true);
  const [isDecryptModalOpen, setIsDecryptModalOpen] = useState(false);
  const [selectedMessage, setSelectedMessage] = useState(null); // To store the message being decrypted

  // Removed logout and navigate from here as they are now in Header
  // const { logout } = useContext(AuthContext);
  // const navigate = useNavigate();

  useEffect(() => {
    const fetchMessages = async () => {
      try {
        setLoadingMessages(true);
        const response = await axiosInstance.get("/messages/inbox");
        const sortedMessages = response.data.sort(
          (a, b) =>
            new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
        );
        setMessages(sortedMessages);
        toast.success("Messages loaded!");
      } catch (error) {
        console.error("Failed to fetch messages:", error);
        toast.error(
          "Failed to load messages: " + (error.response?.data || error.message)
        );
      } finally {
        setLoadingMessages(false);
      }
    };

    fetchMessages();
  }, []);

  // Removed handleLogout as it's now in Header
  // const handleLogout = async () => { ... };

  // const handleComposeMessage = () => {
  //   // This will navigate to a new page/modal for composing messages
  //    navigate('/compose'); // This will be handled by the Sidebar
  // };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();

    if (isNaN(date)) {
      return "Invalid Date";
    }

    if (date.getFullYear() === now.getFullYear()) {
      return date.toLocaleString("en-IN", { month: "short", day: "numeric" });
    } else {
      return date.toLocaleString("en-IN", {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
    }
  };

  // Function to open the decrypt modal
  const openDecryptModal = (message) => {
    setSelectedMessage(message);
    setIsDecryptModalOpen(true);
  };

  // Function to close the decrypt modal
  const closeDecryptModal = () => {
    setIsDecryptModalOpen(false);
    setSelectedMessage(null); // Clear selected message when closing
    // Optionally, re-fetch messages or update the specific message if its status changed
    // e.g., if you want to mark it as read after decryption
  };

 return (
    <>
      <Header />
      <div className="main-dashboard-layout">
        <Sidebar />
        <div className="inbox-content-area">
          {loadingMessages ? (
            <div className="loading-wrapper">
              <p className="loading-text">Loading messages...</p>
            </div>
          ) : messages.length === 0 ? (
            <p className="no-messages-text">No messages in your inbox yet.</p>
          ) : (
            <div className="messages-list">
              {messages.map((message) => (
                <div key={message.messageId} className="message-item">
                  <div className="message-actions-left">
                    <input type="checkbox" className="message-checkbox" />
                    <span className="message-star" title="Mark as important">
                      ⭐
                    </span>
                  </div>
                  <div className="message-content-main">
                    <span className="message-sender">
                      {message.senderUsername}
                    </span>
                    <p className="message-preview">
                      {message.encryptedContent.slice(0, 70)}...
                    </p>
                    <span className="message-encryption-type">
                      Algorithm: {message.encryptionType}
                    </span>
                  </div>
                  <div className="message-actions-right">
                    <span className="message-timestamp">
                      {formatTimestamp(message.timestamp)}
                    </span>
                    <button
                      className="decrypt-btn"
                      onClick={() => openDecryptModal(message)}
                    >
                      Decrypt
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      {isDecryptModalOpen && selectedMessage && (
        <DecryptModal message={selectedMessage} onClose={closeDecryptModal} />
      )}
    </>
  );
}