import React, { useEffect, useState, useCallback } from "react"; // Added useCallback
import { toast } from "react-toastify";
import axiosInstance from "../api/axiosInstance";
import Header from "../components/Header";
import "../css/Dashboard.css";
import Sidebar from "../components/Sidebar";
import DecryptModal from "../components/DecryptModal";
import { API_BASE_URL } from "../config/config";

export default function Dashboard() {
  const [messages, setMessages] = useState([]);
  const [loadingMessages, setLoadingMessages] = useState(true);
  const [isDecryptModalOpen, setIsDecryptModalOpen] = useState(false);
  const [selectedMessage, setSelectedMessage] = useState(null); // To store the message being decrypted

  // Memoize fetchMessages to prevent unnecessary re-creations
  const fetchMessages = useCallback(async () => {
    try {
      setLoadingMessages(true);
      const response = await axiosInstance.get("/messages/inbox");
      const sortedMessages = response.data.sort(
        (a, b) =>
          new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      );
      setMessages(sortedMessages);
      // toast.success("Messages loaded!"); // Removed toast for initial load, can be noisy
    } catch (error) {
      console.error("Failed to fetch messages:", error);
      toast.error(
        "Failed to load messages: " +
          (error.response?.data?.message || error.message)
      );
    } finally {
      setLoadingMessages(false);
    }
  }, []); // No dependencies for initial fetch

  useEffect(() => {
    fetchMessages(); // Fetch messages on component mount

    // --- SSE Integration Start ---

    const eventSource = new EventSource(`${API_BASE_URL}/messages/stream`);

    eventSource.onopen = () => {
      console.log("SSE connection opened.");
      toast.info("Real-time updates connected!");
    };

    eventSource.addEventListener("new-message", (event) => {
      console.log('New message event data (named "new-message"):', event.data);
      try {
        const newMessage = JSON.parse(event.data);
        setMessages((prevMessages) => {
          if (
            prevMessages.some((msg) => msg.messageId === newMessage.messageId)
          ) {
            console.log(
              "Duplicate message received via SSE, skipping:",
              newMessage.messageId
            );
            return prevMessages;
          }
          const updatedMessages = [newMessage, ...prevMessages];
          return updatedMessages.sort(
            (a, b) =>
              new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
          );
        });
        toast.success(`New message from ${newMessage.senderUsername}!`);
      } catch (e) {
        console.error(
          'Error parsing SSE message for "new-message" event:',
          e,
          event.data
        );
        toast.error(
          'Failed to parse real-time message for "new-message" event.'
        );
      }
    });

    eventSource.onmessage = (event) => {
      console.log("New message event:", event.data);
      try {
        const newMessage = JSON.parse(event.data);
        setMessages((prevMessages) => {
          // Check if message already exists (e.g., if re-fetching also occurred)
          if (
            prevMessages.some((msg) => msg.messageId === newMessage.messageId)
          ) {
            return prevMessages; // Message already in list, do not add
          }
          // Add new message and sort by timestamp
          const updatedMessages = [newMessage, ...prevMessages];
          return updatedMessages.sort(
            (a, b) =>
              new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
          );
        });
        toast.success(`New message from ${newMessage.senderUsername}!`);
      } catch (e) {
        console.error("Error parsing SSE message:", e, event.data);
        toast.error("Failed to parse real-time message.");
      }
    };

    eventSource.onerror = (error) => {
      console.error("SSE Error:", error);
      // Check for specific error types if needed
      // For example, if the server sends an error message on the stream
      toast.error(
        "Real-time updates disconnected. Please refresh if issues persist."
      );
      eventSource.close(); // Close the connection to prevent constant errors
    };

    // Cleanup function for useEffect
    return () => {
      console.log("SSE connection closed.");
      eventSource.close(); // Close the connection when the component unmounts
    };
    // --- SSE Integration End ---
  }, [fetchMessages]); // Dependency array: Re-run effect if fetchMessages changes (though memoized)

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();

    if (isNaN(date)) {
      return "Invalid Date";
    }

    if (date.getFullYear() === now.getFullYear()) {
      return date.toLocaleString("en-IN", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }); // Added time
    } else {
      return date.toLocaleString("en-IN", {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit", // Added time
      });
    }
  };

  const openDecryptModal = (message) => {
    setSelectedMessage(message);
    setIsDecryptModalOpen(true);
  };

  const closeDecryptModal = () => {
    setIsDecryptModalOpen(false);
    setSelectedMessage(null);
    // Optionally: Re-fetch the message list to update any read/decrypted status
    // fetchMessages(); // Uncomment this if you want to refresh the entire inbox after decryption
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
            <div className="message-list">
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
        <DecryptModal message={selectedMessage} onClose={closeDecryptModal} />
      )}
    </>
  );
}
