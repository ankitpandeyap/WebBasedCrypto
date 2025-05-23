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
  const [encryptionType, setEncryptionType] = useState("AES");
  const [loading, setLoading] = useState(false);
  const [availableUsers, setAvailableUsers] = useState([]);
  const [filteredSuggestions, setFilteredSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);

  const navigate = useNavigate();
  const autocompleteRef = useRef(null); // Ref for the autocomplete container

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const response = await axiosInstance.get("/users/all");
        setAvailableUsers(response.data);
      } catch (error) {
        console.error("Failed to fetch users:", error);
        // We will address the 401 error separately.
      }
    };
    fetchUsers();
  }, []);

  useEffect(() => {
    if (recipient.length > 0) {
      const filtered = availableUsers.filter((user) =>
        user.username.toLowerCase().includes(recipient.toLowerCase()) ||
        user.email.toLowerCase().includes(recipient.toLowerCase())
      );
      setFilteredSuggestions(filtered);
      // Only show suggestions if there are actual matches AND the input is focused
      // We will control visibility more strictly with onBlur/onFocus
    } else {
      setFilteredSuggestions([]);
    }
  }, [recipient, availableUsers]);

  // Handle click outside suggestions to close them
  useEffect(() => {
    const handleClickOutside = (event) => {
      // If the click is outside the autocomplete container, hide suggestions
      if (autocompleteRef.current && !autocompleteRef.current.contains(event.target)) {
        setShowSuggestions(false);
      }
    };

    // Attach event listener to the document
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      // Clean up the event listener on unmount
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []); // Empty dependency array because autocompleteRef.current is stable

  const handleSuggestionClick = (username, event) => {
    // Stop the event from bubbling up to the document's mousedown listener
    event.stopPropagation();
    setRecipient(username);
    setShowSuggestions(false); // Hide suggestions after selection
  };

  // When input is focused, show suggestions if there's text
  const handleInputFocus = () => {
    if (recipient.length > 0 && filteredSuggestions.length > 0) {
      setShowSuggestions(true);
    }
  };

  // When input loses focus, hide suggestions (with a slight delay to allow click on suggestion)
  const handleInputBlur = () => {
    // Use a small timeout to allow the handleSuggestionClick to fire before blur hides it
    setTimeout(() => {
      setShowSuggestions(false);
    }, 100);
  };


  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axiosInstance.post("/messages/send", {
        toUsername: recipient,
        rawMessage: messageContent,
        algorithm: encryptionType,
      });
      toast.success(response.data || "Message sent successfully!");
      navigate("/dashboard");
    } catch (error) {
      console.error("Failed to send message:", error);
      toast.error(
        "Failed to send message: " + (error.response?.data || error.message)
      );
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
              <div className="form-group recipient-autocomplete" ref={autocompleteRef}>
                <label htmlFor="recipient" className="form-label">
                  To:
                </label>
                <input
                  id="recipient"
                  type="text"
                  value={recipient}
                  onChange={(e) => setRecipient(e.target.value)}
                  onFocus={handleInputFocus} // Use new focus handler
                  onBlur={handleInputBlur}   // Use new blur handler
                  placeholder="Recipient username or Email NOTE:PRESENT IN SYSTEM"
                  required
                  className="form-input"
                />
                {showSuggestions && filteredSuggestions.length > 0 && (
                  <ul className="suggestions-list">
                    {filteredSuggestions.map((user) => (
                      <li
                        key={user.id}
                        // Pass the event object to stop propagation
                        onClick={(e) => handleSuggestionClick(user.username, e)}
                        className="suggestion-item"
                      >
                        {user.username} ({user.email})
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="form-group">
                <label htmlFor="messageContent" className="form-label">
                  Message:
                </label>
                <textarea
                  id="messageContent"
                  value={messageContent}
                  onChange={(e) => setMessageContent(e.target.value)}
                  placeholder="Your message content"
                  rows="8"
                  required
                  className="form-textarea"
                ></textarea>
              </div>

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
                  <option value="CAESAR">Caesar</option>
                  <option value="MONO_ALPHABETIC_CIPHER">Monoalphabetic</option>
                  <option value="CUSTOM">Custom</option>
                </select>
                {(encryptionType === "CAESAR" ||
                  encryptionType === "MONO_ALPHABETIC_CIPHER" ||
                  encryptionType === "CUSTOM") && (
                  <p className="algorithm-warning">
                    Warning: Caesar, Monoalphabetic, and Custom ciphers are not
                    secure for sensitive data.
                  </p>
                )}
              </div>

              <button
                type="submit"
                disabled={loading}
                className="compose-submit-btn"
              >
                {loading ? "Sending..." : "Send Message"}
              </button>
            </form>
          </div>
        </div>
      </div>
    </>
  );
}