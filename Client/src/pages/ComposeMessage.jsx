import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import axiosInstance from "../api/axiosInstance";
import Header from "../components/Header";
import Sidebar from "../components/Sidebar";
import "../css/ComposeMessage.css";

export default function ComposeMessage() {
    const [recipient, setRecipient] = useState("");
    const [messageContent, setMessageContent] = useState("");
    const [selectedFile, setSelectedFile] = useState(null);
    const [encryptionType, setEncryptionType] = useState("AES");
    const [loading, setLoading] = useState(false);
    const [availableUsers, setAvailableUsers] = useState([]);
    const [filteredSuggestions, setFilteredSuggestions] = useState([]);
    const [showSuggestions, setShowSuggestions] = useState(false);
    const [composeMode, setComposeMode] = useState("message"); // 'message' or 'file'

    const navigate = useNavigate();
    const autocompleteRef = useRef(null);
    const fileInputRef = useRef(null);

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const response = await axiosInstance.get("/users/all");
                setAvailableUsers(response.data);
            } catch (error) {
                console.error("Failed to fetch users:", error);
            }
        };
        fetchUsers();
    }, []);

    useEffect(() => {
        if (recipient.length > 0) {
            const filtered = availableUsers.filter(
                (user) =>
                    user.username.toLowerCase().includes(recipient.toLowerCase()) ||
                    user.email.toLowerCase().includes(recipient.toLowerCase())
            );
            setFilteredSuggestions(filtered);
        } else {
            setFilteredSuggestions([]);
        }
    }, [recipient, availableUsers]);

    useEffect(() => {
        const handleClickOutside = (event) => {
            if (
                autocompleteRef.current &&
                !autocompleteRef.current.contains(event.target)
            ) {
                setShowSuggestions(false);
            }
        };

        document.addEventListener("mousedown", handleClickOutside);
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
        };
    }, []);

    const handleSuggestionClick = (username, event) => {
        event.stopPropagation();
        setRecipient(username);
        setShowSuggestions(false);
    };

    const handleInputFocus = () => {
        if (recipient.length > 0 && filteredSuggestions.length > 0) {
            setShowSuggestions(true);
        }
    };

    const handleInputBlur = () => {
        setTimeout(() => {
            setShowSuggestions(false);
        }, 100);
    };

    const handleFileChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            setSelectedFile(file);
            setMessageContent(""); // Clear message content when a file is selected
            toast.info(`File selected: ${file.name}`);
        }
    };

    const handleChooseFileClick = () => {
        fileInputRef.current?.click();
    };

    const handleComposeModeChange = (mode) => {
        setComposeMode(mode);
        if (mode === "message") {
            setSelectedFile(null);
            if (fileInputRef.current) {
                fileInputRef.current.value = ''; // Clear file input field
            }
        } else {
            setMessageContent("");
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);

        let dataToSend; // This will hold either JSON or FormData
        let endpoint = "";
        let contentType = "";

        if (composeMode === "file") {
            if (!selectedFile) {
                toast.error("Please select a file to send.");
                setLoading(false);
                return;
            }
            dataToSend = new FormData();
            dataToSend.append("toUsername", recipient);
            dataToSend.append("algorithm", encryptionType);
            dataToSend.append("file", selectedFile);
            endpoint = "/messages/send-file";
            contentType = "multipart/form-data"; // axios will set this automatically, but good to be explicit
        } else {
            // composeMode === 'message'
            if (!messageContent.trim()) {
                toast.error("Please provide a message.");
                setLoading(false);
                return;
            }
            dataToSend = { // This is a plain JavaScript object, will be sent as JSON
                toUsername: recipient,
                algorithm: encryptionType,
                rawMessage: messageContent,
            };
            endpoint = "/messages/send";
            contentType = "application/json"; // axios will set this based on dataToSend type, but good to be explicit
        }

        try {
            const config = {
                headers: {
                    "Content-Type": contentType, // Explicitly set content type based on mode
                },
            };

            const response = await axiosInstance.post(endpoint, dataToSend, config);
            toast.success(response.data || "Message sent successfully!");
            navigate("/dashboard");
        } catch (error) {
            console.error("Failed to send message:", error);
            // It's good to check for error.response?.data and error.response?.data?.error
            // because your backend returns Map.of("error", "...")
            const errorMessage = error.response?.data?.error || error.response?.data || error.message;
            toast.error("Failed to send message: " + errorMessage);
        } finally {
            setLoading(false);
        }
    };

    return (
        <>
            <Header />
            <div className="main-dashboard-layout">
                <Sidebar />
                <div className="compose-container">
                    <div className="compose-box">
                        <h1 className="compose-title">Compose New Message</h1>
                        <form onSubmit={handleSubmit} className="compose-form">
                            <div
                                className="form-group recipient-autocomplete"
                                ref={autocompleteRef}
                            >
                                <label htmlFor="recipient" className="form-label">
                                    To:
                                </label>
                                <input
                                    id="recipient"
                                    type="text"
                                    value={recipient}
                                    onChange={(e) => setRecipient(e.target.value)}
                                    onFocus={handleInputFocus}
                                    onBlur={handleInputBlur}
                                    placeholder="Recipient username or Email NOTE:PRESENT IN SYSTEM"
                                    required
                                    className="form-input"
                                />
                                {showSuggestions && filteredSuggestions.length > 0 && (
                                    <ul className="suggestions-list">
                                        {filteredSuggestions.map((user) => (
                                            <li
                                                key={user.id}
                                                onClick={(e) => handleSuggestionClick(user.username, e)}
                                                className="suggestion-item"
                                            >
                                                {user.username} ({user.email})
                                            </li>
                                        ))}
                                    </ul>
                                )}
                            </div>

                            <div className="form-group message-type-selection">
                                <label className="form-label">Select Content Type:</label>
                                <div className="radio-group">
                                    <label>
                                        <input
                                            type="radio"
                                            value="message"
                                            checked={composeMode === "message"}
                                            onChange={() => handleComposeModeChange("message")}
                                        />
                                        Type Message
                                    </label>
                                    <label>
                                        <input
                                            type="radio"
                                            value="file"
                                            checked={composeMode === "file"}
                                            onChange={() => handleComposeModeChange("file")}
                                        />
                                        Send File
                                    </label>
                                </div>
                            </div>

                            {composeMode === "message" && (
                                <div className="form-group">
                                    <label htmlFor="messageContent" className="form-label">
                                        Message Content:
                                    </label>
                                    <textarea
                                        id="messageContent"
                                        value={messageContent}
                                        onChange={(e) => setMessageContent(e.target.value)}
                                        placeholder="Type your message here..."
                                        rows="8"
                                        className="form-textarea"
                                    ></textarea>
                                </div>
                            )}

                            {composeMode === "file" && (
                                <div className="form-group">
                                    <label htmlFor="fileInput" className="form-label">
                                        File to Send:
                                    </label>
                                    {selectedFile ? (
                                        <p className="selected-file-info">
                                            Selected File: <strong>{selectedFile.name}</strong> (
                                            {(selectedFile.size / 1024).toFixed(2)} KB)
                                            <button
                                                type="button"
                                                onClick={() => setSelectedFile(null)}
                                                className="clear-file-btn"
                                            >
                                                Clear File
                                            </button>
                                        </p>
                                    ) : (
                                        <p className="no-file-selected">No file chosen.</p>
                                    )}
                                    <input
                                        type="file"
                                        ref={fileInputRef}
                                        onChange={handleFileChange}
                                        style={{ display: "none" }}
                                        id="fileInput"
                                    />
                                    <button
                                        type="button"
                                        onClick={handleChooseFileClick}
                                        className="choose-file-btn"
                                    >
                                        {selectedFile ? "Change File" : "Choose File"}
                                    </button>
                                </div>
                            )}

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
                                    <option value="MONO_ALPHABETIC_CIPHER">Monoalphabetic</option>
                                    <option value="CUSTOM">Custom</option>
                                </select>
                                {(encryptionType === "MONO_ALPHABETIC_CIPHER" ||
                                    encryptionType === "CUSTOM") && (
                                        <p className="algorithm-warning">
                                            Warning: Monoalphabetic, and Custom ciphers are not secure
                                            for sensitive data.
                                        </p>
                                    )}
                            </div>

                            <button
                                type="submit"
                                disabled={
                                    loading ||
                                    recipient.trim() === "" ||
                                    (composeMode === "message" && messageContent.trim() === "") ||
                                    (composeMode === "file" && !selectedFile)
                                }
                                className="compose-submit-btn"
                            >
                                {loading
                                    ? composeMode === "file"
                                        ? "Uploading..."
                                        : "Sending..."
                                    : composeMode === "file"
                                        ? "Send File"
                                        : "Send Message"}
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </>
    );
}