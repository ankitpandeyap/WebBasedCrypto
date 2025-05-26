// src/pages/Dashboard.jsx
import React, { useEffect, useState, useCallback, useContext } from "react";
import { toast } from "react-toastify";
import axiosInstance from "../api/axiosInstance";
import Header from "../components/Header";
import "../css/Dashboard.css";
import Sidebar from "../components/Sidebar";
import DecryptModal from "../components/DecryptModal";

import { AuthContext } from "../context/AuthContext";
import { SseContext } from "../context/SseContext"; // Import SseContext to consume messages
import { useNavigate } from "react-router-dom";

export default function Dashboard() {
  const { accessToken, loadingAuth } = useContext(AuthContext);
  // Consume receivedMessages and connection status from SseContext
  const { receivedMessages } = useContext(SseContext);
  const navigate = useNavigate();

  // State to hold all messages (fetched from API + received via SSE)
  const [messages, setMessages] = useState([]);
  const [loadingMessages, setLoadingMessages] = useState(true);
  const [isDecryptModalOpen, setIsDecryptModalOpen] = useState(false);
  const [selectedMessage, setSelectedMessage] = useState(null);

  // REMOVE: eventSourceRef and hasConnectedRef - SSE connection is global now

  // Function to fetch messages from the backend API
  const fetchMessages = useCallback(async () => {
    try {
      setLoadingMessages(true);
      const response = await axiosInstance.get("/messages/inbox");
      const fetchedMessages = response.data;

      // Combine fetched messages with any messages already accumulated in SseContext
      // This ensures messages received while on other pages are also displayed.
      setMessages((prevMessages) => {
          const combined = [...fetchedMessages]; // Start with freshly fetched messages
          receivedMessages.forEach(sseMsg => {
              // Add SSE messages only if they are not already present in the fetched list
              if (!combined.some(fetchedMsg => fetchedMsg.messageId === sseMsg.messageId)) {
                  combined.push(sseMsg);
              }
          });
          // Sort the combined list by timestamp (latest first)
          return combined.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      });

    } catch (error) {
      console.error("Failed to fetch messages:", error);
      toast.error(
        "Failed to load messages: " +
          (error.response?.data?.message || error.message)
      );
    } finally {
      setLoadingMessages(false);
    }
  }, [receivedMessages]); // Re-run fetchMessages if new SSE messages arrive while Dashboard is mounted

  // REMOVE: connectToSSE and disconnectSSE functions as they are now in SseContext

  // Effect to handle initial loading and authentication check
  useEffect(() => {
    if (loadingAuth) return; // Wait until authentication status is known

    if (!accessToken) {
      toast.error("Session expired. Please log in.");
      navigate("/login");
      return;
    }

    // Fetch initial messages when the component mounts and auth is ready
    fetchMessages();

    // No cleanup for SSE connection here, as it's managed by SseContext
    // The SSE connection will persist even if Dashboard unmounts
  }, [fetchMessages, accessToken, loadingAuth, navigate]);

  // Effect to update the 'messages' state whenever 'receivedMessages' from SseContext changes.
  // This handles real-time updates while the user is on the Dashboard page.
  useEffect(() => {
    setMessages((prevMessages) => {
        const updatedMessages = [...prevMessages];
        receivedMessages.forEach(sseMsg => {
            if (!updatedMessages.some(msg => msg.messageId === sseMsg.messageId)) {
                updatedMessages.push(sseMsg);
            }
        });
        return updatedMessages.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    });
  }, [receivedMessages]); // This effect runs whenever receivedMessages array changes

  // Helper function to format message timestamps
  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    if (isNaN(date)) return "Invalid Date"; // Handle invalid date inputs

    // Format based on whether the message is from the current year
    if (date.getFullYear() === now.getFullYear()) {
      return date.toLocaleString("en-IN", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } else {
      return date.toLocaleString("en-IN", {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    }
  };

  // Functions to manage the decrypt modal
  const openDecryptModal = (message) => {
    setSelectedMessage(message);
    setIsDecryptModalOpen(true);
  };

  const closeDecryptModal = () => {
    setIsDecryptModalOpen(false);
    setSelectedMessage(null);
  };


 const handleMarkAsReadAfterDecryption = async (messageId) => {
    try {

      await axiosInstance.patch(`/messages/${messageId}/read`, {
        isRead: true, // Explicitly set to true
      });

      setMessages((prevMessages) =>
        prevMessages.map((msg) =>
          msg.messageId === messageId ? { ...msg, isRead: true } : msg
        )
      );
      toast.success("Message marked as read.");
    } catch (error) {
      console.error("Failed to mark message as read after decryption:", error);
      toast.error("Failed to mark message as read automatically.");
    }
  };

  const handleMarkAsStarred = async (messageId, currentIsStarredStatus) => {
    const newIsStarredStatus = !currentIsStarredStatus; // Toggle the status
    try {
      await axiosInstance.patch(`/messages/${messageId}/star`, {
        isStarred: newIsStarredStatus,
      });

      // Optimistically update UI
      setMessages((prevMessages) =>
        prevMessages.map((msg) =>
          msg.messageId === messageId ? { ...msg, isStarred: newIsStarredStatus } : msg
        )
      );
      toast.success(
        `Message ${newIsStarredStatus ? "marked as important" : "unmarked as important"}.`
      );
    } catch (error) {
      console.error("Failed to update starred status:", error);
      toast.error(
        "Failed to update starred status: " +
          (error.response?.data?.message || error.message)
      );
      // Revert UI if API call fails
      setMessages((prevMessages) =>
        prevMessages.map((msg) =>
          msg.messageId === messageId ? { ...msg, isStarred: currentIsStarredStatus } : msg
        )
      );
    }
  };


   return (
    <>
      <Header />
      <div className="main-dashboard-layout">
        <Sidebar />
        <div className="inbox-content-area">
          {loadingMessages && messages.length === 0 ? (
            <div className="loading-wrapper">
              <p className="loading-text">Loading messages...</p>
            </div>
          ) : messages.length === 0 ? (
            <p className="no-messages-text">No messages in your inbox yet.</p>
          ) : (
            <div className="message-list">
              {messages.map((message) => (
                <div
                  key={message.messageId}
                  className={`message-item ${
                    message.isRead ? "message-read" : "message-unread"
                  }`}
                >
                  <div className="message-actions-left">
                    {/* CONDITIONAL RENDERING OF STAR SVG */}
                    <span
                      className="message-star" // No 'starred' class needed here, color controlled by SVG fill
                      title="Mark as important"
                      onClick={() => handleMarkAsStarred(message.messageId, message.isStarred)}
                    >
                      {message.isStarred ? (
                        // Filled star SVG
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          viewBox="0 0 24 24"
                          fill="currentColor" // This will be #ffca28 from CSS
                          width="24px"
                          height="24px"
                        >
                          <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.25l-6.18 3.25L7 14.14l-5-4.87 6.91-1.01L12 2z" />
                        </svg>
                      ) : (
                        // Hollow star SVG
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          viewBox="0 0 24 24"
                          fill="none" // No fill for hollow
                          stroke="currentColor" // This will be #ccc from CSS
                          strokeWidth="2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          width="24px"
                          height="24px"
                        >
                          <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.18 12 17.25 5.82 21.18 7 14.14 2 9.27 8.91 8.26 12 2" />
                        </svg>
                      )}
                    </span>
                  </div>

                  <div className="message-content-main">
                    <span className="message-sender">
                      {message.senderUsername}
                    </span>
                    <p className="message-subject">
                      {message.encryptedContent.substring(0, 70)}...
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
        <DecryptModal
          message={selectedMessage}
          onClose={closeDecryptModal}
          isSentView={false}
          onDecryptSuccess={handleMarkAsReadAfterDecryption}
        />
      )}
    </>
  );
}