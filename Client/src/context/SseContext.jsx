// src/context/SseContext.js
import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from 'react';
import { toast } from 'react-toastify';
import { EventSource } from 'eventsource'; // Assuming you still use this polyfill
import { API_BASE_URL } from '../config/config';
import { AuthContext } from './AuthContext';

export const SseContext = createContext();

export const SseProvider = ({ children }) => {
    const { accessToken, loadingAuth } = useContext(AuthContext);
    const eventSourceRef = useRef(null);
    const [receivedMessages, setReceivedMessages] = useState([]);
    const [isConnected, setIsConnected] = useState(false);

    // HIGHLIGHTED CHANGE START: Add a ref for the reconnect timeout
    const reconnectTimeoutRef = useRef(null);
    // HIGHLIGHTED CHANGE END


const clearReconnectTimeout = useCallback(() => {
        if (reconnectTimeoutRef.current) {
            clearTimeout(reconnectTimeoutRef.current);
            reconnectTimeoutRef.current = null;
            console.log("Cleared pending SSE reconnect timeout.");
        }
    }, []);
    // HIGHLIGHTED CHANGE END

     // HIGHLIGHTED CHANGE START: Update disconnectSSE to clear timeout
    const disconnectSSE = useCallback(() => {
        clearReconnectTimeout(); // Always clear any pending reconnects first
        if (eventSourceRef.current) {
            console.log("SSE connection explicitly closed by SseContext.");
            eventSourceRef.current.close();
            eventSourceRef.current = null;
            setIsConnected(false);
        }
    }, [clearReconnectTimeout]);
    // HIGHLIGHTED CHANGE END

  
    

    const connectToSSE = useCallback(() => {
        if (eventSourceRef.current || !accessToken || loadingAuth) {
            return;
        }

        console.log("Attempting to connect to SSE...");
        const es = new EventSource(`${API_BASE_URL}/messages/stream`, {
            fetch: (input, init) => {
                return fetch(input, {
                    ...init,
                    headers: {
                        ...init?.headers,
                        Authorization: `Bearer ${accessToken}`,
                    },
                });
            },
        });

        es.onopen = () => {
            console.log("SSE connection opened globally.");
            toast.info("Real-time updates connected!");
            setIsConnected(true);
            // HIGHLIGHTED CHANGE START: Clear any pending reconnects on successful open
            clearReconnectTimeout();
            // HIGHLIGHTED CHANGE END
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
            setIsConnected(false); // Update connection status

            // HIGHLIGHTED CHANGE START: Specific handling for 401 Unauthorized errors
            if (error.status === 401 || (error.message && error.message.includes('401'))) {
                console.warn("SSE received 401 Unauthorized. Disconnecting and not immediately attempting reconnect.");
                disconnectSSE(); // Disconnect immediately, do not schedule automatic reconnect for 401
                toast.error("Authentication required for real-time updates. Please log in again if issues persist.");
                return; // Exit, do not proceed with generic reconnect logic
            }
            // HIGHLIGHTED CHANGE END

            // For other errors (network, server close, etc.), attempt reconnect
            if (es.readyState === EventSource.CLOSED || es.readyState === EventSource.CONNECTING) {
                toast.warn("SSE connection error. Attempting to reconnect automatically in 5 seconds...");
                // HIGHLIGHTED CHANGE START: Clear existing timeout, then schedule new one
                disconnectSSE(); // Close the current faulty connection cleanly
                if (!reconnectTimeoutRef.current) { // Prevent multiple timeouts
                    reconnectTimeoutRef.current = setTimeout(connectToSSE, 5000);
                }
                // HIGHLIGHTED CHANGE END
            } else {
                toast.error("SSE connection error. Check network or server.");
            }
        };

        eventSourceRef.current = es;

        // HIGHLIGHTED CHANGE START: Add clearReconnectTimeout and disconnectSSE to dependencies
    }, [accessToken, loadingAuth, clearReconnectTimeout, disconnectSSE]);
        // HIGHLIGHTED CHANGE END

    

    useEffect(() => {
        if (!loadingAuth && accessToken) {
            connectToSSE();
        } else if (!accessToken) {
            disconnectSSE();
        }

        return () => {
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