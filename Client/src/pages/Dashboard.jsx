import React, { useEffect, useState, useCallback, useContext } from "react";
import { toast } from "react-toastify";
import axiosInstance from "../api/axiosInstance";
import Header from "../components/Header";
import "../css/Dashboard.css";
import Sidebar from "../components/Sidebar";
import DecryptModal from "../components/DecryptModal";

import { AuthContext } from "../context/AuthContext";
import { SseContext } from "../context/SseContext";
import { useNavigate } from "react-router-dom";

export default function Dashboard() {
    const { accessToken, loadingAuth } = useContext(AuthContext);
    const { receivedMessages, updateSseMessageStatus } = useContext(SseContext);
    const navigate = useNavigate();

    const [messages, setMessages] = useState([]);
    const [loadingMessages, setLoadingMessages] = useState(true);
    const [isDecryptModalOpen, setIsDecryptModalOpen] = useState(false);
    const [selectedMessage, setSelectedMessage] = useState(null);

    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
    const [messageToDelete, setMessageToDelete] = useState(null);

    const fetchMessages = useCallback(async () => {
        try {
            setLoadingMessages(true);
            const response = await axiosInstance.get("/messages/inbox");
            const fetchedMessages = response.data.map(msg => ({
                ...msg,
                isRead: msg.read,
                isStarred: msg.starred
            }));

            setMessages((prevMessages) => {
                const combinedMap = new Map();
                fetchedMessages.forEach(msg => combinedMap.set(msg.messageId, msg));
                receivedMessages.forEach(sseMsg => {
                    const existingMsg = combinedMap.get(sseMsg.messageId);
                    const normalizedSseMsg = {
                        ...sseMsg,
                        isRead: sseMsg.hasOwnProperty('isRead') ? sseMsg.isRead : sseMsg.read,
                        isStarred: sseMsg.hasOwnProperty('isStarred') ? sseMsg.isStarred : sseMsg.starred
                    };
                    combinedMap.set(sseMsg.messageId, { ...existingMsg, ...normalizedSseMsg });
                });
                return Array.from(combinedMap.values()).sort(
                    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
                );
            });

        } catch (error) {
            console.error("Dashboard: Failed to fetch messages:", error); // Keeping console.error for critical errors
            toast.error(
                "Failed to load messages: " +
                (error.response?.data?.message || error.message)
            );
        } finally {
            setLoadingMessages(false);
        }
    }, [receivedMessages]);

    useEffect(() => {
        if (loadingAuth) return;

        if (!accessToken) {
            toast.error("Session expired. Please log in.");
            navigate("/login");
            return;
        }

        fetchMessages();

    }, [fetchMessages, accessToken, loadingAuth, navigate]);

    useEffect(() => {
        setMessages((prevMessages) => {
            const updatedMessagesMap = new Map(prevMessages.map(msg => [msg.messageId, msg]));

            receivedMessages.forEach(sseMsg => {
                const existingMsg = updatedMessagesMap.get(sseMsg.messageId);
                const normalizedSseMsg = {
                    ...sseMsg,
                    isRead: sseMsg.hasOwnProperty('isRead') ? sseMsg.isRead : sseMsg.read,
                    isStarred: sseMsg.hasOwnProperty('isStarred') ? sseMsg.isStarred : sseMsg.starred
                };
                updatedMessagesMap.set(sseMsg.messageId, { ...existingMsg, ...normalizedSseMsg });
            });
            return Array.from(updatedMessagesMap.values()).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        });
    }, [receivedMessages]);

    const formatTimestamp = (timestamp) => {
        const date = new Date(timestamp);
        const now = new Date();
        if (isNaN(date)) return "Invalid Date";

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
                isRead: true,
            });

            setMessages((prevMessages) =>
                prevMessages.map((msg) =>
                    msg.messageId === messageId ? { ...msg, isRead: true } : msg
                )
            );
            updateSseMessageStatus(messageId, { isRead: true });

            toast.success("Message marked as read.");
        } catch (error) {
            console.error("Dashboard: Failed to mark message as read after decryption:", error); // Keeping console.error for critical errors
            toast.error("Failed to mark message as read automatically.");
        }
    };

    const handleMarkAsStarred = async (messageId, currentIsStarredStatus) => {
        const newIsStarredStatus = !currentIsStarredStatus;
        try {
            await axiosInstance.patch(`/messages/${messageId}/star`, {
                isStarred: newIsStarredStatus,
            });

            setMessages((prevMessages) =>
                prevMessages.map((msg) =>
                    msg.messageId === messageId ? { ...msg, isStarred: newIsStarredStatus } : msg
                )
            );
            updateSseMessageStatus(messageId, { isStarred: newIsStarredStatus });

            toast.success(
                `Message ${newIsStarredStatus ? "marked as important" : "unmarked as important"}.`
            );
        } catch (error) {
            console.error("Dashboard: Failed to update starred status:", error); // Keeping console.error for critical errors
            toast.error(
                "Failed to update starred status: " +
                (error.response?.data?.message || error.message)
            );
            setMessages((prevMessages) =>
                prevMessages.map((msg) =>
                    msg.messageId === messageId ? { ...msg, isStarred: currentIsStarredStatus } : msg
                )
            );
            updateSseMessageStatus(messageId, { isStarred: currentIsStarredStatus });
        }
    };

 const openDeleteConfirmModal = (message) => {
        setMessageToDelete(message);
        setShowDeleteConfirm(true);
    };

    // New: Function to close the delete confirmation overlay
    const closeDeleteConfirmModal = () => {
        setShowDeleteConfirm(false);
        setMessageToDelete(null);
    };

    // New: Function to handle the actual deletion after confirmation
    const confirmDeleteMessage = async () => {
        if (!messageToDelete) return;

        try {
            await axiosInstance.delete(`/messages/${messageToDelete.messageId}`);
            setMessages((prevMessages) =>
                prevMessages.filter((msg) => msg.messageId !== messageToDelete.messageId)
            );
            toast.success("Message deleted successfully!");
            closeDeleteConfirmModal(); // Close the modal after successful deletion
        } catch (error) {
            console.error("Dashboard: Failed to delete message:", error);
            toast.error(
                "Failed to delete message: " +
                (error.response?.data?.message || error.message)
            );
            closeDeleteConfirmModal(); // Close the modal even on error
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
                                        <span
                                            className="message-star"
                                            title="Mark as important"
                                            onClick={() => handleMarkAsStarred(message.messageId, message.isStarred)}
                                        >
                                            {message.isStarred ? (
                                                <svg
                                                    xmlns="http://www.w3.org/2000/svg"
                                                    viewBox="0 0 24 24"
                                                    fill="currentColor"
                                                    width="24px"
                                                    height="24px"
                                                >
                                                    <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.25l-6.18 3.25L7 14.14l-5-4.87 6.91-1.01L12 2z" />
                                                </svg>
                                            ) : (
                                                <svg
                                                    xmlns="http://www.w3.org/2000/svg"
                                                    viewBox="0 0 24 24"
                                                    fill="none"
                                                    stroke="currentColor"
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
                                        <button
                                            className="delete-btn"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                openDeleteConfirmModal(message); // Open confirmation overlay
                                            }}
                                        >
                                            Delete
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

            {/* New: Delete Confirmation Overlay */}
            {showDeleteConfirm && (
                <div className="delete-confirm-overlay">
                    <div className="delete-confirm-modal">
                        <h2>Confirm Deletion</h2>
                        <p>Are you sure you want to delete this message? This action cannot be undone.</p>
                        <div className="delete-confirm-actions">
                            <button
                                className="cancel-delete-btn"
                                onClick={closeDeleteConfirmModal}
                            >
                                Cancel
                            </button>
                            <button
                                className="confirm-delete-btn"
                                onClick={confirmDeleteMessage}
                            >
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}