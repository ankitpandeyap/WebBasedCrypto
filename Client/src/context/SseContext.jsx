import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from 'react';
import { toast } from 'react-toastify';
import { EventSource } from 'eventsource';
import { API_BASE_URL } from '../config/config';
import { AuthContext } from './AuthContext'; // Import AuthContext

export const SseContext = createContext();

export const SseProvider = ({ children }) => {
    // Destructure attemptRefreshFromExternal from AuthContext
    const { accessToken, loadingAuth, attemptRefreshFromExternal } = useContext(AuthContext);
    const eventSourceRef = useRef(null);
    const [receivedMessages, setReceivedMessages] = useState([]);
    const [isConnected, setIsConnected] = useState(false);

    const reconnectTimeoutRef = useRef(null);

    // Clears any pending reconnect timeout
    const clearReconnectTimeout = useCallback(() => {
        if (reconnectTimeoutRef.current) {
            clearTimeout(reconnectTimeoutRef.current);
            reconnectTimeoutRef.current = null;
        }
    }, []);

    // Disconnects the current SSE connection
    const disconnectSSE = useCallback(() => {
        clearReconnectTimeout(); // Ensure no pending reconnects when disconnecting
        if (eventSourceRef.current) {
            eventSourceRef.current.close(); // Close the EventSource connection
            eventSourceRef.current = null; // Clear the ref
            setIsConnected(false); // Update connection status
        }
    }, [clearReconnectTimeout]);

    // Connects to the SSE endpoint
    const connectToSSE = useCallback(() => {
        // Prevent connection if already connected, no token, or authentication is still loading
        if (eventSourceRef.current || !accessToken || loadingAuth) {
            return;
        }

        // Create a new EventSource instance
        const es = new EventSource(`${API_BASE_URL}/messages/stream`, {
            // Custom fetch override to include the Authorization header with the current access token
            fetch: (input, init) => {
                return fetch(input, {
                    ...init,
                    headers: {
                        ...init?.headers,
                        Authorization: `Bearer ${accessToken}`, // Use the latest accessToken from state
                    },
                });
            },
        });

        // Event listener for when the SSE connection opens
        es.onopen = () => {
            toast.info("Real-time updates connected!");
            setIsConnected(true); // Update connection status
            clearReconnectTimeout(); // Clear any pending reconnects as connection is established
        };

        // Event listener for custom 'new-message' events
        es.addEventListener("new-message", (event) => {
            try {
                const newMessage = JSON.parse(event.data);
                setReceivedMessages((prevMessages) => {
                    // Prevent duplicate messages based on messageId
                    if (prevMessages.some((msg) => msg.messageId === newMessage.messageId)) {
                        return prevMessages;
                    }
                    const updatedMessages = [newMessage, ...prevMessages];
                    // Sort messages by timestamp in descending order
                    return updatedMessages.sort(
                        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
                    );
                });
                toast.success(`New message from ${newMessage.senderUsername}!`);
            } catch (e) {
                console.error("Error parsing SSE 'new-message':", e, event.data); // Keep console.error for parsing errors
                toast.error("Failed to parse real-time message.");
            }
        });

        // Generic message listener (can be used for heartbeat or other general messages)
        es.onmessage = (event) => {
            // No logging for generic messages unless specific debugging is needed
        };

        // Event listener for SSE errors
        es.onerror = (error) => {
            console.error("SSE Error globally:", error); // Keep console.error for critical SSE errors
            setIsConnected(false); // Set connection status to false on error

            // Handle 401 Unauthorized errors specifically
            if (error.status === 401 || (error.message && error.message.includes('401'))) {
                disconnectSSE(); // Ensure the current faulty SSE connection is closed.
                toast.error("Real-time session expired. Attempting to re-authenticate...");

                // Proactively trigger token refresh using the function from AuthContext
                if (attemptRefreshFromExternal) {
                    attemptRefreshFromExternal();
                }
                // The useEffect below will handle reconnection automatically once accessToken updates
            } else {
                // For other errors (network, server close, etc.), attempt reconnect
                if (es.readyState === EventSource.CLOSED || es.readyState === EventSource.CONNECTING) {
                    toast.warn("SSE connection error. Attempting to reconnect automatically in 5 seconds..."); // Keeping toast.warn as it's user-facing
                    disconnectSSE(); // Close the current faulty connection cleanly
                    if (!reconnectTimeoutRef.current) { // Prevent multiple timeouts
                        reconnectTimeoutRef.current = setTimeout(connectToSSE, 5000);
                    }
                } else {
                    toast.error("SSE connection error. Check network or server.");
                }
            }
        };

        eventSourceRef.current = es; // Store the EventSource instance in the ref

    }, [accessToken, loadingAuth, clearReconnectTimeout, disconnectSSE, attemptRefreshFromExternal]); // Add attemptRefreshFromExternal to dependencies

    // Effect to manage SSE connection based on authentication state
    useEffect(() => {
        if (!loadingAuth && accessToken) {
            // If accessToken is available and we're not already connected, connect
            if (!eventSourceRef.current || eventSourceRef.current.readyState === EventSource.CLOSED) {
                connectToSSE();
            }
        } else if (!accessToken) {
            // If accessToken is null (e.g., logged out, refresh failed), disconnect
            disconnectSSE();
        }

        // Cleanup function: disconnect SSE when component unmounts or dependencies change
        return () => {
            disconnectSSE();
        };
    }, [accessToken, loadingAuth, connectToSSE, disconnectSSE]);

    const updateSseMessageStatus = useCallback((messageId, updates) => {
        setReceivedMessages(prevMessages =>
            prevMessages.map(msg =>
                msg.messageId === messageId ? { ...msg, ...updates } : msg
            )
        );
    }, []);
    // Context value provided to consumers
    const value = {
        receivedMessages,
        isConnected,
        clearReceivedMessages: () => setReceivedMessages([]),
        updateSseMessageStatus,
    };
    return (
        <SseContext.Provider value={value}>
            {children}
        </SseContext.Provider>
    );
};