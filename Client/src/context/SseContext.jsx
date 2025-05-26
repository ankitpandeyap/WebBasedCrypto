// src/context/SseContext.js
import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from 'react';
import { toast } from 'react-toastify';
import { EventSource } from 'eventsource';
import { API_BASE_URL } from '../config/config';
import { AuthContext } from './AuthContext'; // Import AuthContext

export const SseContext = createContext();

export const SseProvider = ({ children }) => {
    // No need to destructure refreshAccessToken or logout here.
    // We will rely on AuthContext's state update.
    const { accessToken, loadingAuth } = useContext(AuthContext);
    const eventSourceRef = useRef(null);
    const [receivedMessages, setReceivedMessages] = useState([]);
    const [isConnected, setIsConnected] = useState(false);

    const reconnectTimeoutRef = useRef(null);

    const clearReconnectTimeout = useCallback(() => {
        if (reconnectTimeoutRef.current) {
            clearTimeout(reconnectTimeoutRef.current);
            reconnectTimeoutRef.current = null;
            console.log("Cleared pending SSE reconnect timeout.");
        }
    }, []);

    const disconnectSSE = useCallback(() => {
        clearReconnectTimeout();
        if (eventSourceRef.current) {
            console.log("SSE connection explicitly closed by SseContext.");
            eventSourceRef.current.close();
            eventSourceRef.current = null;
            setIsConnected(false);
        }
    }, [clearReconnectTimeout]);

    // connectToSSE function does not need to be async now
    const connectToSSE = useCallback(() => {
        if (eventSourceRef.current || !accessToken || loadingAuth) {
            console.log("Skipping SSE connection attempt:", { hasRef: !!eventSourceRef.current, accessToken: !!accessToken, loadingAuth });
            return;
        }

        console.log("Attempting to connect to SSE with token (first 10 chars):", accessToken.substring(0, Math.min(accessToken.length, 10)) + "...");
        const es = new EventSource(`${API_BASE_URL}/messages/stream`, {
            // Your custom fetch override to add Authorization header
            fetch: (input, init) => {
                return fetch(input, {
                    ...init,
                    headers: {
                        ...init?.headers,
                        Authorization: `Bearer ${accessToken}`, // Ensure this always uses the LATEST accessToken from state
                    },
                });
            },
        });

        es.onopen = () => {
            console.log("SSE connection opened globally.");
            toast.info("Real-time updates connected!");
            setIsConnected(true);
            clearReconnectTimeout();
        };

        es.addEventListener("new-message", (event) => {
            try {
                const newMessage = JSON.parse(event.data);
                setReceivedMessages((prevMessages) => {
                    if (prevMessages.some((msg) => msg.messageId === newMessage.messageId)) {
                        return prevMessages;
                    }
                    const updatedMessages = [newMessage, ...prevMessages];
                    return updatedMessages.sort(
                        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
                    );
                });
                toast.success(`New message from ${newMessage.senderUsername}!`);
            } catch (e) {
                console.error("Error parsing SSE 'new-message':", e, event.data);
                toast.error("Failed to parse real-time message.");
            }
        });

        es.onmessage = (event) => {
            // console.log("SSE generic message:", event.data);
        };

        es.onerror = (error) => {
            console.error("SSE Error globally:", error);
            setIsConnected(false);

            if (error.status === 401 || (error.message && error.message.includes('401'))) {
                console.warn("SSE received 401 Unauthorized. Relying on Axios interceptor to refresh token or handle logout.");
                // The Axios interceptor should handle the refresh of the access token
                // and update AuthContext's accessToken state.
                // When AuthContext's accessToken state changes, the useEffect below
                // will trigger a new connectToSSE call.
                disconnectSSE(); // Ensure the current faulty SSE connection is closed.
                toast.error("Real-time session expired. Attempting to re-authenticate...");
                // NO explicit refreshAccessToken() call here.
                // NO setTimeout to reconnect here.
                // The useEffect below handles reconnection automatically once accessToken updates.
            } else {
                // For other errors (network, server close, etc.), attempt reconnect
                if (es.readyState === EventSource.CLOSED || es.readyState === EventSource.CONNECTING) {
                    toast.warn("SSE connection error. Attempting to reconnect automatically in 5 seconds...");
                    disconnectSSE(); // Close the current faulty connection cleanly
                    if (!reconnectTimeoutRef.current) { // Prevent multiple timeouts
                        reconnectTimeoutRef.current = setTimeout(connectToSSE, 5000);
                    }
                } else {
                    toast.error("SSE connection error. Check network or server.");
                }
            }
        };

        eventSourceRef.current = es;

    }, [accessToken, loadingAuth, clearReconnectTimeout, disconnectSSE]);


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

        return () => {
            // Cleanup on component unmount or dependencies change
            disconnectSSE();
        };
    }, [accessToken, loadingAuth, connectToSSE, disconnectSSE]);

    const value = {
        receivedMessages,
        isConnected,
        clearReceivedMessages: () => setReceivedMessages([])
    };

    return (
        <SseContext.Provider value={value}>
            {children}
        </SseContext.Provider>
    );
};