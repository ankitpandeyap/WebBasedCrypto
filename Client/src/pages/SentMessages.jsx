import React, { useState, useEffect, useCallback, useContext } from "react";
import { toast } from "react-toastify";
import axiosInstance from "../api/axiosInstance";
import Header from "../components/Header";
import Sidebar from "../components/Sidebar";
import DecryptModal from "../components/DecryptModal"; // Include DecryptModal for viewing sent message content
import "../css/Dashboard.css"; // Reuse Dashboard CSS for consistent message list styling

import { AuthContext } from "../context/AuthContext";
import { useNavigate } from "react-router-dom";

export default function SentMessages() {
    const { accessToken, loadingAuth } = useContext(AuthContext);
    const navigate = useNavigate();

    const [messages, setMessages] = useState([]);
    const [loadingMessages, setLoadingMessages] = useState(true);
    const [isDecryptModalOpen, setIsDecryptModalOpen] = useState(false);
    const [selectedMessage, setSelectedMessage] = useState(null);

    // Function to fetch sent messages from the backend API
    const fetchSentMessages = useCallback(async () => {
        try {
            setLoadingMessages(true);
            const response = await axiosInstance.get("/messages/sent"); // Calls the new backend endpoint
            setMessages(response.data);
        } catch (error) {
            console.error("Failed to fetch sent messages:", error); // Keeping console.error for critical errors
            toast.error(
                "Failed to load sent messages: " +
                (error.response?.data?.message || error.message)
            );
        } finally {
            setLoadingMessages(false);
        }
    }, []);

    // Effect to handle initial loading and authentication check
    useEffect(() => {
        if (loadingAuth) return; // Wait until authentication status is known

        if (!accessToken) {
            toast.error("Session expired. Please log in.");
            navigate("/login");
            return;
        }

        // Fetch sent messages when the component mounts and auth is ready
        fetchSentMessages();
    }, [fetchSentMessages, accessToken, loadingAuth, navigate]);

    // Helper function to format message timestamps (reused from Dashboard.jsx)
    const formatTimestamp = (timestamp) => {
        const date = new Date(timestamp);
        const now = new Date();
        if (isNaN(date)) return "Invalid Date";

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

    // Functions to manage the decrypt modal for viewing sent messages
    const openDecryptModal = (message) => {
        setSelectedMessage(message);
        setIsDecryptModalOpen(true);
    };

    const closeDecryptModal = () => {
        setIsDecryptModalOpen(false);
        setSelectedMessage(null);
    };

    return (
        <>
            <Header />
            <div className="main-dashboard-layout">
                <Sidebar />
                <div className="inbox-content-area">
                    <h1 className="messages-section-title">Sent Messages</h1>
                    {loadingMessages && messages.length === 0 ? (
                        <div className="loading-wrapper">
                            <p className="loading-text">Loading sent messages...</p>
                        </div>
                    ) : messages.length === 0 ? (
                        <p className="no-messages-text">No messages in your sent folder yet.</p>
                    ) : (
                        <div className="message-list">
                            {messages.map((message) => (
                                <div key={message.messageId} className="message-item message-read"> {/* NEW: Always apply message-read class */}
                                    <div className="message-actions-left">
                                        {/* Checkbox and Star are intentionally removed for sent messages */}
                                    </div>

                                    <div className="message-content-main">
                                        <span className="message-sender">
                                            To: {message.receiverUsername}
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
                                            View
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
                    isSentView={true} // Keep this true for sent view
                />
            )}
        </>
    );
}