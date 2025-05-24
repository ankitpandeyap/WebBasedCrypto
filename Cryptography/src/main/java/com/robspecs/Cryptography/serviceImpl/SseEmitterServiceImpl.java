package com.robspecs.Cryptography.serviceImpl;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import com.fasterxml.jackson.core.JsonProcessingException; // Specific import
import com.fasterxml.jackson.databind.ObjectMapper;
import com.robspecs.Cryptography.dto.MessageSummaryDTO; // Import your DTO
import com.robspecs.Cryptography.service.SseEmitterService;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

@Service
public class SseEmitterServiceImpl implements SseEmitterService {
    private static final Logger log = LoggerFactory.getLogger(SseEmitterServiceImpl.class);
    private final ConcurrentHashMap<String, List<SseEmitter>> emitters = new ConcurrentHashMap<>();
    private static final Long SSE_TIMEOUT_MILLIS = 300_000L; // 5 minutes
    private static final long HEARTBEAT_INTERVAL_SECONDS = 30;

    private ScheduledExecutorService heartbeatExecutor;
    private final ScheduledExecutorService sendExecutor = Executors.newScheduledThreadPool(4); // Thread pool for offloading send tasks

    private final ConcurrentHashMap<SseEmitter, Integer> inFlightEvents = new ConcurrentHashMap<>(); // Track in-flight events per emitter

    private final ObjectMapper objectMapper; // Inject ObjectMapper

    // Constructor to inject ObjectMapper
    public SseEmitterServiceImpl(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        log.info("SseEmitterServiceImpl initialized with ObjectMapper.");
    }

    @PostConstruct
    public void init() {
        heartbeatExecutor = Executors.newScheduledThreadPool(4);
        log.info("SSE Heartbeat scheduler initialized.");

        heartbeatExecutor.scheduleAtFixedRate(() -> {
            emitters.forEach((username, userEmitters) -> {
                // Iterate over a copy to avoid ConcurrentModificationException if emitters are removed during iteration
                new CopyOnWriteArrayList<>(userEmitters).forEach(emitter -> {
                    try {
                        emitter.send(SseEmitter.event().comment("heartbeat"));
                        // log.trace("Sent SSE heartbeat to user: {}", username); // Use trace for frequent logs
                    } catch (IOException e) {
                        log.warn("Failed to send SSE heartbeat to user '{}', removing emitter due to: {}", username, e.getMessage());
                        removeEmitter(username, emitter);
                    } catch (IllegalStateException e) {
                        // This typically means the emitter was already closed from the client side
                        log.debug("SSE heartbeat failed, emitter for user '{}' already closed or completed: {}", username, e.getMessage());
                        removeEmitter(username, emitter);
                    }
                });
            });
        }, 0, HEARTBEAT_INTERVAL_SECONDS, TimeUnit.SECONDS);
        log.info("SSE Heartbeat task scheduled to run every {} seconds.", HEARTBEAT_INTERVAL_SECONDS);
    }

    @PreDestroy
    public void destroy() {
        shutdownExecutor(heartbeatExecutor, "SSE Heartbeat scheduler", 5);
        shutdownExecutor(sendExecutor, "SSE Send Executor", 10);

        emitters.forEach((username, userEmitters) -> {
            userEmitters.forEach(emitter -> {
                emitter.complete();
                log.debug("Completed SSE emitter for user {} during shutdown.", username);
            });
        });
        emitters.clear();
        inFlightEvents.clear();
        log.info("All SSE emitters cleared during shutdown.");
    }

    private void shutdownExecutor(ScheduledExecutorService executor, String name, long timeoutSeconds) {
        if (executor != null && !executor.isShutdown()) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(timeoutSeconds, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                    log.warn("{} forced shutdown.", name);
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
                log.warn("{} shutdown interrupted.", name);
            }
            log.info("{} shut down.", name);
        }
    }


    @Override
    public SseEmitter createEmitter(String username) {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT_MILLIS);
        emitters.computeIfAbsent(username, k -> new CopyOnWriteArrayList<>()).add(emitter);
        inFlightEvents.put(emitter, 0); // Start with 0 in-flight events

        try {
            // Send an initial CONNECT event to confirm the connection is active
            emitter.send(SseEmitter.event()
                    .name("CONNECT") // A custom event name, helpful for client
                    .data("Connection established.") // Simple data to confirm connection
                    .id(String.valueOf(System.currentTimeMillis()))); // Unique ID for this event
            log.info("Sent initial CONNECT event to SSE emitter for user: {}", username);
        } catch (IOException e) {
            log.error("Failed to send initial CONNECT event to SSE emitter for user {}: {}", username, e.getMessage());
            removeEmitter(username, emitter);
            // Don't rethrow here if you want the connection to silently fail instead of throwing a server error
            // However, for debugging, rethrowing or returning null might be useful
            return null; // Indicate failure to the calling controller
        }

        emitter.onCompletion(() -> {
            log.info("SSE emitter completed for user: {}", username);
            removeEmitter(username, emitter);
        });
        emitter.onTimeout(() -> {
            log.warn("SSE emitter timed out for user: {}", username);
            removeEmitter(username, emitter);
        });
        emitter.onError(e -> {
            log.error("SSE emitter error for user {}: {}", username, e.getMessage());
            removeEmitter(username, emitter);
        });

        log.info("SSE emitter created for user: {}", username);
        return emitter;
    }

    @Override
    public void sendEvent(String username, Object payload) {
        List<SseEmitter> userEmitters = emitters.get(username);
        if (userEmitters == null || userEmitters.isEmpty()) {
            log.info("No active SSE emitters found for user: {} to send event.", username);
            return;
        }

        String jsonPayload;
        try {
            jsonPayload = objectMapper.writeValueAsString(payload); // Convert DTO to JSON string
            log.debug("Converted payload to JSON for user {}: {}", username, jsonPayload);
        } catch (JsonProcessingException e) { // Catch JsonProcessingException specifically
            log.error("Failed to serialize payload to JSON for user {}: {}", username, e.getMessage(), e);
            return; // Don't attempt to send if serialization fails
        }

        // Iterate over a copy to safely remove emitters if they break during iteration
        for (SseEmitter emitter : new CopyOnWriteArrayList<>(userEmitters)) {
            sendExecutor.submit(() -> { // Submit to thread pool (non-blocking)
                try {
                    inFlightEvents.computeIfPresent(emitter, (k, v) -> v + 1); // Track in-flight count

                    // Use the specific event name your frontend expects, e.g., "new-message"
                    emitter.send(SseEmitter.event().name("new-message").data(jsonPayload));
                    log.info("Successfully sent new-message event to SSE emitter for user: {} (Payload: {})", username, jsonPayload.substring(0, Math.min(jsonPayload.length(), 100)) + "..."); // Log a snippet of payload

                } catch (IOException e) {
                    log.warn("Failed to send SSE to user '{}', removing emitter. Error: {}", username, e.getMessage());
                    removeEmitter(username, emitter);
                } catch (IllegalStateException e) {
                    log.warn("SSE emitter for user '{}' was already closed/completed, removing. Error: {}", username, e.getMessage());
                    removeEmitter(username, emitter);
                } finally {
                    inFlightEvents.computeIfPresent(emitter, (k, v) -> Math.max(0, v - 1)); // Decrement in-flight count
                }
            });
        }
    }

    private void removeEmitter(String username, SseEmitter emitter) {
        List<SseEmitter> userEmitters = emitters.get(username);
        if (userEmitters != null) {
            userEmitters.remove(emitter);
            inFlightEvents.remove(emitter); // Remove tracking
            log.info("Removed SSE emitter for user: {}", username);
            if (userEmitters.isEmpty()) {
                emitters.remove(username);
                log.info("Removed all SSE emitters for user: {} (list is now empty).", username);
            }
        }
        // Also call emitter.complete() explicitly to clean up resources, if not already done by Spring
        try {
            emitter.complete();
        } catch (Exception e) {
            log.error("Error completing SSE emitter for user {}: {}", username, e.getMessage());
        }
    }
}