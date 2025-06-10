import React, { useState, useEffect } from "react";
import axiosInstance from "../api/axiosInstance";
import { toast } from "react-toastify";
import "../css/DecryptModal.css";

export default function DecryptModal({ message, onClose, isSentView, onDecryptSuccess, onFileDownload }) {
    const [passkey, setPasskey] = useState("");
    const [decryptedContent, setDecryptedContent] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    // Reset state when message changes (modal reopened or new message)
    useEffect(() => {
        setPasskey("");
        setDecryptedContent(null);
        setError(null);
        setLoading(false);
    }, [message]);

    const handleAction = async (e) => { // Renamed from handleDecrypt to handleAction
        e.preventDefault();
        if (!message?.messageId) {
            setError("No message selected.");
            return;
        }
        setLoading(true);
        setError(null);
        setDecryptedContent(null);

        try {
            if (message.isFile) {
                // If it's a file, call the onFileDownload prop
                if (onFileDownload) {
                    await onFileDownload(message.messageId, passkey);
                    onClose(); // Close modal after initiating download
                } else {
                    throw new Error("File download handler not provided.");
                }
            } else {
                // Existing decryption logic for text messages
                const { data } = await axiosInstance.post(
                    `/messages/${message.messageId}/decrypt`,
                    null, // no body payload
                    {
                        params: { passkey }, // send passkey as query parameter
                    }
                );
                setDecryptedContent(data.decryptedContent);
                toast.success("Message decrypted successfully!");

                // Only call onDecryptSuccess if it's provided and not a sent message view
                if (onDecryptSuccess && !isSentView) {
                    onDecryptSuccess(message.messageId);
                }
            }
        } catch (err) {
            const errMsg = err.response?.data?.error || err.response?.data?.message || err.response?.data || err.message || (message.isFile ? "Failed to download file." : "Failed to decrypt message.");
            setError(errMsg);
            toast.error(`${message.isFile ? "Download" : "Decryption"} failed: ${errMsg}`);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="decrypt-modal-backdrop" onClick={onClose}>
            <div className="decrypt-modal-content" onClick={(e) => e.stopPropagation()}>
                <button
                    aria-label="Close modal"
                    className="decrypt-modal-close-btn"
                    onClick={onClose}
                >
                    ×
                </button>

                <h2>{message?.isFile ? "Download File" : "Decrypt Message"} (ID: {message?.messageId || "N/A"})</h2>
                {isSentView ? (
                    <p className="decrypt-modal-sender">
                        To: {message?.receiverUsername || "Unknown"}
                    </p>
                ) : (
                    <p className="decrypt-modal-sender">
                        From: {message?.senderUsername || "Unknown"}
                    </p>
                )}
                {/* NEW: Display file name if it's a file message */}
                {message?.isFile && message?.originalFileName && (
                    <p className="decrypt-modal-filename">
                        File: **{message.originalFileName}** ({message.contentType})
                    </p>
                )}


                {/* NEW: Only show decrypted content for text messages, not files */}
                {decryptedContent && !message.isFile ? (
                    <>
                        <div className="decrypt-output-container">
                            <h3>Decrypted Content:</h3>
                            <p className="decrypt-output-text">{decryptedContent}</p>
                        </div>
                        <button className="decrypt-done-btn" onClick={onClose}>
                            Done
                        </button>
                    </>
                ) : (
                    <form onSubmit={handleAction} className="decrypt-form" noValidate> {/* Changed onSubmit to handleAction */}
                        <label htmlFor="passkey-input" className="decrypt-form-label">
                            Enter Passkey:
                        </label>
                        <input
                            id="passkey-input"
                            type="password"
                            value={passkey}
                            onChange={(e) => setPasskey(e.target.value)}
                            placeholder="Your passkey"
                            required
                            className="decrypt-form-input"
                            autoFocus
                            disabled={loading}
                        />
                        <button
                            type="submit"
                            disabled={loading || passkey.trim() === ""}
                            className="decrypt-submit-btn"
                            aria-busy={loading}
                        >
                            {/* NEW: Dynamic button text */}
                            {loading ? (message.isFile ? "Downloading..." : "Decrypting...") : (message.isFile ? "Download" : "Decrypt")}
                        </button>
                    </form>
                )}

                {error && (
                    <p className="decrypt-error-message" role="alert">
                        {error}
                    </p>
                )}
            </div>
        </div>
    );
}