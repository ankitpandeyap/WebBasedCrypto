import React, { useState, useEffect, useCallback, useContext } from "react";
import { toast } from "react-toastify";
import axiosInstance from "../api/axiosInstance";
import Header from "../components/Header";
import Sidebar from "../components/Sidebar";
import DecryptModal from "../components/DecryptModal";
import "../css/Dashboard.css";

import { AuthContext } from "../context/AuthContext";
import { useNavigate } from "react-router-dom";

export default function SentMessages() {
    const { accessToken, loadingAuth } = useContext(AuthContext);
    const navigate = useNavigate();

    const [messages, setMessages] = useState([]);
    const [loadingMessages, setLoadingMessages] = useState(true);
    const [isDecryptModalOpen, setIsDecryptModalOpen] = useState(false);
    const [selectedMessage, setSelectedMessage] = useState(null);

    const fetchSentMessages = useCallback(async () => {
        try {
            setLoadingMessages(true);
            const response = await axiosInstance.get("/messages/sent");
            const normalizedMessages = response.data.map(msg => ({
                ...msg,
                isFile: msg.file,
                // Safely create displayContent for text messages
                displayContent: msg.file
                    ? ''
                    : (msg.encryptedContent
                        ? (msg.encryptedContent.substring(0, 70) + (msg.encryptedContent.length > 70 ? '...' : ''))
                        : 'No content preview available') // Fallback if encryptedContent is null/undefined
            }));
            setMessages(normalizedMessages);
        } catch (error) {
            console.error("Failed to fetch sent messages:", error);
            toast.error(
                "Failed to load sent messages: " +
                (error.response?.data?.message || error.message)
            );
        } finally {
            setLoadingMessages(false);
        }
    }, []); // Removed messages from dependency array to prevent infinite loop

    useEffect(() => {
        if (loadingAuth) return;

        if (!accessToken) {
            toast.error("Session expired. Please log in.");
            navigate("/login");
            return;
        }

        fetchSentMessages();
    }, [fetchSentMessages, accessToken, loadingAuth, navigate]);

    const formatTimestamp = useCallback((timestamp) => {
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
    }, []);

    const openDecryptModal = (message) => {
        setSelectedMessage(message);
        setIsDecryptModalOpen(true);
    };

    const closeDecryptModal = () => {
        setIsDecryptModalOpen(false);
        setSelectedMessage(null);
    };

    const handleDownloadFile = async (messageId, passkey) => {
        try {
            const response = await axiosInstance.get(`/messages/${messageId}/download`, {
                params: { passkey },
                responseType: 'blob',
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
            });

            const contentDisposition = response.headers['content-disposition'];
            let filename = `downloaded_file_${messageId}`;
            if (contentDisposition) {
                const filenameMatch = contentDisposition.match(/filename="([^"]+)"/);
                if (filenameMatch && filenameMatch[1]) {
                    filename = filenameMatch[1];
                }
            } else if (selectedMessage && selectedMessage.originalFileName) {
                filename = selectedMessage.originalFileName;
            }

            const url = window.URL.createObjectURL(new Blob([response.data], { type: response.headers['content-type'] }));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', filename);
            document.body.appendChild(link);
            link.click();
            link.parentNode.removeChild(link);
            window.URL.revokeObjectURL(url);

            toast.success(`File "${filename}" downloaded successfully!`);
        } catch (error) {
            console.error("SentMessages: Failed to download file:", error);
            let errMsg = "An unknown error occurred during download.";
            if (error.response && error.response.data) {
                if (error.response.data instanceof Blob) {
                    const errorText = await error.response.data.text();
                    try {
                        const errorJson = JSON.parse(errorText);
                        errMsg = errorJson.message || errorJson.error || errMsg;
                    } catch (e) {
                        errMsg = errorText;
                    }
                } else if (error.response.data.message) {
                    errMsg = error.response.data.message;
                } else if (error.response.data.error) {
                    errMsg = error.response.data.error;
                }
            } else if (error.message) {
                errMsg = error.message;
            }
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
                            <p className="loading-text">Loading sent messages...</p>
                        </div>
                    ) : messages.length === 0 ? (
                        <p className="no-messages-text">No messages in your sent folder yet.</p>
                    ) : (
                        <div className="message-list">
                            {messages.map((message) => (
                                <div key={message.messageId} className="message-item message-read">
                                    <div className="message-actions-left">
                                        {/* Checkbox and Star are intentionally removed for sent messages */}
                                    </div>

                                    <div className="message-content-main">
                                        <span className="message-sender">
                                            To: {message.receiverUsername}
                                        </span>
                                        {/* Using displayContent for summary, and originalFileName for file types */}
                                        {message.isFile ? (
                                            <p className="message-subject">
                                                <i className="fas fa-file"></i> <strong>{message.originalFileName}</strong> ({message.contentType})
                                            </p>
                                        ) : (
                                            <p className="message-subject">
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
                                        {message.isFile ? (
                                            <button
                                                className="action-btn download-btn"
                                                onClick={() => openDecryptModal(message)}
                                            >
                                                Download File
                                            </button>
                                        ) : (
                                            <button
                                                className="decrypt-btn"
                                                onClick={() => openDecryptModal(message)}
                                            >
                                                View
                                            </button>
                                        )}
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
                    isSentView={true}
                    onFileDownload={handleDownloadFile}
                />
            )}
        </>
    );
}