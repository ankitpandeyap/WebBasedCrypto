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
	private static final long HEARTBEAT_INTERVAL_SECONDS = 30;

	private ScheduledExecutorService heartbeatExecutor;

	// ✅ New: Thread pool for offloading send tasks
	private final ScheduledExecutorService sendExecutor = Executors.newScheduledThreadPool(4);

	// ✅ New: Track in-flight events per emitter
	private final ConcurrentHashMap<SseEmitter, Integer> inFlightEvents = new ConcurrentHashMap<>();

	@PostConstruct
	public void init() {
		// Use a ScheduledThreadPool with 4 threads for heartbeats (multi-threaded)
		heartbeatExecutor = Executors.newScheduledThreadPool(4);
		log.info("SSE Heartbeat scheduler initialized.");

		heartbeatExecutor.scheduleAtFixedRate(() -> {
			emitters.forEach((username, userEmitters) -> {
				userEmitters.forEach(emitter -> {
					try {
						emitter.send(SseEmitter.event().comment("heartbeat"));
					} catch (IOException e) {
						log.warn("Failed to send SSE heartbeat to user '{}', removing emitter due to: {}", username,
								e.getMessage());
						removeEmitter(username, emitter);
					}
				});
			});
		}, 0, HEARTBEAT_INTERVAL_SECONDS, TimeUnit.SECONDS);
		log.info("SSE Heartbeat task scheduled to run every {} seconds.", HEARTBEAT_INTERVAL_SECONDS);
	}

	@PreDestroy
	public void destroy() {
		// Shutdown heartbeatExecutor gracefully
		if (heartbeatExecutor != null && !heartbeatExecutor.isShutdown()) {
			heartbeatExecutor.shutdown();
			try {
				if (!heartbeatExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
					heartbeatExecutor.shutdownNow();
					log.warn("SSE Heartbeat scheduler forced shutdown.");
				}
			} catch (InterruptedException e) {
				heartbeatExecutor.shutdownNow();
				Thread.currentThread().interrupt();
				log.warn("SSE Heartbeat scheduler shutdown interrupted.");
			}
			log.info("SSE Heartbeat scheduler shut down.");
		}

		// ✅ IMPROVEMENT: Shutdown sendExecutor gracefully (similar to
		// heartbeatExecutor)
		if (sendExecutor != null && !sendExecutor.isShutdown()) {
			sendExecutor.shutdown(); // Initiate graceful shutdown
			try {
				if (!sendExecutor.awaitTermination(10, TimeUnit.SECONDS)) { // Give more time for event sending
					sendExecutor.shutdownNow(); // Force shutdown if not terminated
					log.warn("SSE Send Executor forced shutdown.");
				}
			} catch (InterruptedException e) {
				sendExecutor.shutdownNow();
				Thread.currentThread().interrupt(); // Restore interrupt status
				log.warn("SSE Send Executor shutdown interrupted.");
			}
			log.info("SSE Send Executor shut down.");
		}

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

	@Override
	public SseEmitter createEmitter(String username) {
		SseEmitter emitter = new SseEmitter(SSE_TIMEOUT_MILLIS);
		emitters.computeIfAbsent(username, k -> new CopyOnWriteArrayList<>()).add(emitter);
		inFlightEvents.put(emitter, 0); // ✅ Start with 0 in-flight events

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

		for (SseEmitter emitter : new CopyOnWriteArrayList<>(userEmitters)) {
			// ✅ Submit to thread pool (non-blocking)
			sendExecutor.submit(() -> {
				try {
					// ✅ Track in-flight count
					inFlightEvents.computeIfPresent(emitter, (k, v) -> v + 1);

					emitter.send(SseEmitter.event().name("new-message").data(payload));
					log.info("Sent new-message event to SSE emitter for user: {}", username);

				} catch (IOException e) {
					log.warn("Failed to send SSE to {}, removing emitter", username, e);
					removeEmitter(username, emitter);
				} catch (IllegalStateException e) {
					log.warn("SSE emitter for user '{}' was already closed/completed, removing. Error: {}", username,
							e.getMessage());
					removeEmitter(username, emitter);
				} finally {
					// ✅ Decrement in-flight count
					inFlightEvents.computeIfPresent(emitter, (k, v) -> Math.max(0, v - 1));
				}
			});
		}
	}

	private void removeEmitter(String username, SseEmitter emitter) {
		List<SseEmitter> userEmitters = emitters.get(username);
		if (userEmitters != null) {
			userEmitters.remove(emitter);
			inFlightEvents.remove(emitter); // ✅ Remove tracking
			log.info("Removed SSE emitter for user: {}", username);
			if (userEmitters.isEmpty()) {
				emitters.remove(username);
				log.info("Removed all SSE emitters for user: {} (list is now empty).", username);
			}
		}
	}
}
