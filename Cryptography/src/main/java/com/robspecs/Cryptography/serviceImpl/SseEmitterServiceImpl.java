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

import com.robspecs.Cryptography.service.SseEmitterService;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

@Service
public class SseEmitterServiceImpl implements SseEmitterService {
	private static final Logger log = LoggerFactory.getLogger(SseEmitterServiceImpl.class);
	private final ConcurrentHashMap<String, List<SseEmitter>> emitters = new ConcurrentHashMap<>();

	private static final Long SSE_TIMEOUT_MILLIS = 300_000L; // 5 minutes

    // Define heartbeat interval (e.g., every 30 seconds)
    private static final long HEARTBEAT_INTERVAL_SECONDS = 30;

    // ScheduledExecutorService for sending heartbeats
    private ScheduledExecutorService heartbeatExecutor;

    @PostConstruct
    public void init() {
        // Create a single-threaded scheduler for heartbeats.
        // This ensures heartbeats are sent periodically without blocking other operations.
        heartbeatExecutor = Executors.newSingleThreadScheduledExecutor();
        log.info("SSE Heartbeat scheduler initialized.");

        // Schedule the heartbeat task to run periodically.
        // It will send a comment event to all active emitters.
        heartbeatExecutor.scheduleAtFixedRate(() -> {
            emitters.forEach((username, userEmitters) -> {
                userEmitters.forEach(emitter -> {
                    try {
                        // Send a comment event to keep the connection alive.
                        // Comment events are ignored by EventSource on the client side.
                        emitter.send(SseEmitter.event().comment("heartbeat"));
                    } catch (IOException e) {
                        // Log a warning if sending heartbeat fails and remove the problematic emitter.
                        log.warn("Failed to send SSE heartbeat to user '{}', removing emitter due to: {}", username, e.getMessage());
                        removeEmitter(username, emitter);
                    }
                });
            });
        }, 0, HEARTBEAT_INTERVAL_SECONDS, TimeUnit.SECONDS); // Start immediately, then every HEARTBEAT_INTERVAL_SECONDS
        log.info("SSE Heartbeat task scheduled to run every {} seconds.", HEARTBEAT_INTERVAL_SECONDS);
    }

    @PreDestroy
    public void destroy() {
        if (heartbeatExecutor != null && !heartbeatExecutor.isShutdown()) {
            heartbeatExecutor.shutdown(); // Initiate graceful shutdown
            try {
                // Wait for the scheduled tasks to terminate gracefully
                if (!heartbeatExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    heartbeatExecutor.shutdownNow(); // Force shutdown if not terminated
                    log.warn("SSE Heartbeat scheduler forced shutdown.");
                }
            } catch (InterruptedException e) {
                heartbeatExecutor.shutdownNow();
                Thread.currentThread().interrupt(); // Restore interrupt status
                log.warn("SSE Heartbeat scheduler shutdown interrupted.");
            }
            log.info("SSE Heartbeat scheduler shut down.");
        }

        // Also ensure all active emitters are completed/closed on shutdown
        emitters.forEach((username, userEmitters) -> {
            userEmitters.forEach(emitter -> {
                emitter.complete(); // Signal completion to all active emitters
                log.debug("Completed SSE emitter for user {} during shutdown.", username);
            });
        });
        emitters.clear(); // Clear the map
        log.info("All SSE emitters cleared during shutdown.");
    }

	@Override
	public SseEmitter createEmitter(String username) {
		SseEmitter emitter = new SseEmitter(SSE_TIMEOUT_MILLIS); // Use the defined timeout
		emitters.computeIfAbsent(username, k -> new CopyOnWriteArrayList<>()).add(emitter);

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
		if (userEmitters == null) {
			  log.info("No active SSE emitters found for user: {}", username);
			return;
		}

		// Iterate through a copy to avoid ConcurrentModificationException if emitters are removed during iteration
        for (SseEmitter emitter : new CopyOnWriteArrayList<>(userEmitters)) {
			try {
				emitter.send(SseEmitter.event().name("new-message").data(payload));
				  log.info("Sent new-message event to SSE emitter for user: {}", username);
			} catch (IOException e) {
				log.warn("Failed to send SSE to {}, removing emitter", username, e);
				removeEmitter(username, emitter);
			}catch (IllegalStateException e) {
                // This can happen if the emitter is already closed/completed but not yet removed from the list
                log.warn("SSE emitter for user '{}' was already closed/completed, removing. Error: {}", username, e.getMessage());
                removeEmitter(username, emitter);
            }
		}
	}

	private void removeEmitter(String username, SseEmitter emitter) {
		List<SseEmitter> userEmitters = emitters.get(username);
		if (userEmitters != null) {
			userEmitters.remove(emitter);
			log.info("Removed SSE emitter for user: {}", username);
			if (userEmitters.isEmpty()) {
				emitters.remove(username);
				log.info("Removed all SSE emitters for user: {} (list is now empty).", username);
			}
		}
	}
}
