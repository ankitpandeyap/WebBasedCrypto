import React, { useState, useEffect } from "react";
import axiosInstance from "../api/axiosInstance";
import { toast } from "react-toastify";
import "../css/DecryptModal.css";

export default function DecryptModal({ message, onClose, isSentView, onDecryptSuccess }) {
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

    const handleDecrypt = async (e) => {
        e.preventDefault();
        if (!message?.messageId) {
            setError("No message selected for decryption.");
            return;
        }
        setLoading(true);
        setError(null);
        setDecryptedContent(null);

        try {
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

        } catch (err) {
            // Improved error message extraction from backend response
            const errMsg = err.response?.data?.error || err.response?.data?.message || err.response?.data || err.message || "Failed to decrypt message.";
            setError(errMsg);
            toast.error(`Decryption failed: ${errMsg}`);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="decrypt-modal-backdrop" onClick={onClose}>
            <div className="decrypt-modal-content" onClick={(e) => e.stopPropagation()}>
                <button
                    aria-label="Close decrypt modal"
                    className="decrypt-modal-close-btn"
                    onClick={onClose}
                >
                    ×
                </button>

                <h2>Decrypt Message (ID: {message?.messageId || "N/A"})</h2>
                {isSentView ? (
                    <p className="decrypt-modal-sender">
                        To: {message?.receiverUsername || "Unknown"}
                    </p>
                ) : (
                    <p className="decrypt-modal-sender">
                        From: {message?.senderUsername || "Unknown"}
                    </p>
                )}

                {decryptedContent ? (
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
                    <form onSubmit={handleDecrypt} className="decrypt-form" noValidate>
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
                            {loading ? "Decrypting..." : "Decrypt"}
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