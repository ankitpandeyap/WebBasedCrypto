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
                isStarred: msg.starred,
                isFile: msg.file,
                // Add a displayContent for non-file messages to show snippet
                displayContent: msg.file
                    ? '' // If it's a file, no content preview needed here
                    : (msg.encryptedContent // Check if encryptedContent exists
                        ? (msg.encryptedContent.substring(0, 70) + (msg.encryptedContent.length > 70 ? '...' : ''))
                        : 'No content preview available') // Fallback if encryptedContent is null/undefined
            }));

            setMessages((prevMessages) => {
                const combinedMap = new Map();
                fetchedMessages.forEach(msg => combinedMap.set(msg.messageId, msg));
                receivedMessages.forEach(sseMsg => {
                    const existingMsg = combinedMap.get(sseMsg.messageId);
                    const normalizedSseMsg = {
                        ...sseMsg,
                        isRead: sseMsg.hasOwnProperty('isRead') ? sseMsg.isRead : sseMsg.read,
                        isStarred: sseMsg.hasOwnProperty('isStarred') ? sseMsg.isStarred : sseMsg.starred,
                        isFile: sseMsg.file,
                        // Ensure displayContent is updated for SSE messages too with safety check
                        displayContent: sseMsg.file
                            ? ''
                            : (sseMsg.encryptedContent
                                ? (sseMsg.encryptedContent.substring(0, 70) + (sseMsg.encryptedContent.length > 70 ? '...' : ''))
                                : 'No content preview available')
                    };
                    combinedMap.set(sseMsg.messageId, { ...existingMsg, ...normalizedSseMsg });
                });
                return Array.from(combinedMap.values()).sort(
                    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
                );
            });

        } catch (error) {
            console.error("Dashboard: Failed to fetch messages:", error);
            toast.error(
                "Failed to load messages: " +
                (error.response?.data?.message || error.message)
            );
        } finally {
            setLoadingMessages(false);
        }
    }, [receivedMessages]); // Keep receivedMessages in dependency array for real-time updates

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
                    isStarred: sseMsg.hasOwnProperty('isStarred') ? sseMsg.isStarred : sseMsg.starred,
                    isFile: sseMsg.file,
                    // Ensure displayContent is updated for SSE messages too with safety check
                    displayContent: sseMsg.file
                        ? ''
                        : (sseMsg.encryptedContent
                            ? (sseMsg.encryptedContent.substring(0, 70) + (sseMsg.encryptedContent.length > 70 ? '...' : ''))
                            : 'No content preview available')
                };
                updatedMessagesMap.set(sseMsg.messageId, { ...existingMsg, ...normalizedSseMsg });
            });
            return Array.from(updatedMessagesMap.values()).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        });
    }, [receivedMessages]); // Keep receivedMessages in dependency array for real-time updates


    // The rest of your Dashboard.jsx code remains the same as previously provided,
    // including formatTimestamp, openDecryptModal, closeDecryptModal,
    // handleMarkAsReadAfterDecryption, handleMarkAsStarred, openDeleteConfirmModal,
    // closeDeleteConfirmModal, confirmDeleteMessage, handleDownloadFile, and the JSX return.
    // Just ensure you copy-paste the whole file.

    // ... (rest of the Dashboard.jsx code)

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
            console.error("Dashboard: Failed to mark message as read after decryption:", error);
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
            console.error("Dashboard: Failed to update starred status:", error);
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

    const closeDeleteConfirmModal = () => {
        setShowDeleteConfirm(false);
        setMessageToDelete(null);
    };

    const confirmDeleteMessage = async () => {
        if (!messageToDelete) return;

        try {
            await axiosInstance.delete(`/messages/${messageToDelete.messageId}`);
            setMessages((prevMessages) =>
                prevMessages.filter((msg) => msg.messageId !== messageToDelete.messageId)
            );
            toast.success("Message deleted successfully!");
            closeDeleteConfirmModal();
        } catch (error) {
            console.error("Dashboard: Failed to delete message:", error);
            toast.error(
                "Failed to delete message: " +
                (error.response?.data?.message || error.message)
            );
            closeDeleteConfirmModal();
        }
    };

    const handleDownloadFile = async (messageId, passkey) => {
        try {
            const response = await axiosInstance.get(`/messages/${messageId}/download`, {
                params: { passkey },
                responseType: 'blob', // Essential for downloading binary data
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
            });

            // Extract filename from Content-Disposition header, fallback to message data
            const contentDisposition = response.headers['content-disposition'];
            let filename = `downloaded_file_${messageId}`; // Default fallback
            if (contentDisposition) {
                const filenameMatch = contentDisposition.match(/filename="([^"]+)]+"?/); // Adjusted regex
                if (filenameMatch && filenameMatch[1]) {
                    filename = filenameMatch[1];
                }
            } else if (selectedMessage && selectedMessage.originalFileName) {
                filename = selectedMessage.originalFileName;
            }

            // Create a URL for the blob and trigger download
            const url = window.URL.createObjectURL(new Blob([response.data], { type: response.headers['content-type'] }));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', filename);
            document.body.appendChild(link);
            link.click(); // Programmatically click the link to trigger download
            link.parentNode.removeChild(link); // Clean up the link element
            window.URL.revokeObjectURL(url); // Clean up the object URL

            toast.success(`File "${filename}" downloaded successfully!`);

            // Optionally mark message as read after successful download
            if (selectedMessage && !selectedMessage.isRead) {
                handleMarkAsReadAfterDecryption(messageId);
            }
        } catch (error) {
            console.error("Dashboard: Failed to download file:", error);
            // Check for specific error response structures
            let errMsg = "An unknown error occurred during download.";
            if (error.response && error.response.data) {
                // If it's a blob, we need to read it as text to get the error message
                if (error.response.data instanceof Blob) {
                    const errorText = await error.response.data.text();
                    try {
                        const errorJson = JSON.parse(errorText);
                        errMsg = errorJson.message || errorJson.error || errMsg;
                    } catch (e) {
                        errMsg = errorText; // Fallback to raw text if not JSON
                    }
                } else if (error.response.data.message) {
                    errMsg = error.response.data.message;
                } else if (error.response.data.error) {
                    errMsg = error.response.data.error;
                }
            } else if (error.message) {
                errMsg = error.message;
            }
            // Re-throw the error so DecryptModal can display its own toast/error state
            throw new Error(errMsg);
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
                                        {/* UPDATED: Conditional display for file vs. text message content */}
                                        {message.isFile ? (
                                            <p className="message-subject">
                                                <i className="fas fa-file file-icon"></i> **{message.originalFileName}** ({message.contentType})
                                            </p>
                                        ) : (
                                            <p className="message-subject">
                                                {/* Display snippet of encryptedContent */}
                                                <strong>{message.displayContent}</strong>
                                            </p>
                                        )}
                                        <span className="message-encryption-type">
                                            Algorithm: {message.encryptionType}
                                        </span>
                                    </div>

                                    <div className="message-actions-right">
                                        <span className="message-timestamp">
                                            {formatTimestamp(message.timestamp)}
                                        </span>
                                        {/* Conditional button for Download vs. Decrypt */}
                                        {message.isFile ? (
                                            <button
                                                className="action-btn download-btn"
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    openDecryptModal(message);
                                                }}
                                            >
                                                Download File
                                            </button>
                                        ) : (
                                            <button
                                                className="decrypt-btn"
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    openDecryptModal(message);
                                                }}
                                            >
                                                Decrypt
                                            </button>
                                        )}
                                        <button
                                            className="delete-btn"
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                openDeleteConfirmModal(message);
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
                    onFileDownload={handleDownloadFile}
                />
            )}

            {/* Existing Delete Confirmation Overlay */}
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