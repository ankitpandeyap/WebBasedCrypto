import React, { useState, useEffect } from 'react';
import axiosInstance from '../api/axiosInstance';
import { toast } from 'react-toastify';
import '../css/DecryptModal.css';

export default function DecryptModal({ message, onClose }) {
    const [passkey, setPasskey] = useState('');
    const [decryptedContent, setDecryptedContent] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    // Reset state when a new message is passed (e.g., modal is reopened for a different message)
    useEffect(() => {
        setPasskey('');
        setDecryptedContent(null);
        setError(null);
        setLoading(false);
    }, [message]);

    const handleDecrypt = async (e) => {
        e.preventDefault(); // Prevent default form submission
        setLoading(true);
        setError(null);
        setDecryptedContent(null); // Clear previous decrypted content

        if (!message || !message.messageId) {
            setError('No message selected for decryption.');
            setLoading(false);
            return;
        }

        try {
            const response = await axiosInstance.post('/messages/decrypt', {
                messageId: message.messageId,
                passkey: passkey,
            });
            setDecryptedContent(response.data.decryptedContent);
            toast.success('Message decrypted successfully!');
        } catch (err) {
            console.error('Decryption failed:', err);
            setError(err.response?.data || 'Failed to decrypt message.');
            toast.error('Decryption failed: ' + (err.response?.data || 'Server error'));
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="modal-backdrop">
            <div className="modal-content">
                <button className="modal-close-btn" onClick={onClose}>×</button> {/* Close button */}
                
                <h2>Decrypt Message (ID: {message?.messageId})</h2>
                <p className="modal-sender">From: {message?.senderUsername}</p>

                {decryptedContent ? (
                    <div className="decrypted-area">
                        <h3>Decrypted Content:</h3>
                        <p className="decrypted-text">{decryptedContent}</p>
                    </div>
                ) : (
                    <form onSubmit={handleDecrypt} className="decrypt-form">
                        <label htmlFor="passkey-input" className="form-label">
                            Enter Passkey:
                        </label>
                        <input
                            id="passkey-input"
                            type="password"
                            value={passkey}
                            onChange={(e) => setPasskey(e.target.value)}
                            placeholder="Your passkey"
                            required
                            className="form-input"
                        />
                        <button type="submit" disabled={loading} className="decrypt-submit-btn">
                            {loading ? 'Decrypting...' : 'Decrypt'}
                        </button>
                    </form>
                )}

                {error && <p className="modal-error">{error}</p>}
                
                {/* Optional: Add a button to close the modal after decryption */}
                {decryptedContent && (
                    <button className="modal-done-btn" onClick={onClose}>Done</button>
                )}
            </div>
        </div>
    );
}
