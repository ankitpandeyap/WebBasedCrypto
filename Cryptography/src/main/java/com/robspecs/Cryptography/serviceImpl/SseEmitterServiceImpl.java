package com.robspecs.Cryptography.serviceImpl;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import com.robspecs.Cryptography.controllers.MessageController;
import com.robspecs.Cryptography.service.SseEmitterService;

public class SseEmitterServiceImpl implements SseEmitterService {
	private static final Logger log = LoggerFactory.getLogger(SseEmitterServiceImpl.class);
	 private final ConcurrentHashMap<String, List<SseEmitter>> emitters = new ConcurrentHashMap<>();

	    public SseEmitter createEmitter(String username) {
	        SseEmitter emitter = new SseEmitter(0L); // no timeout
	        emitters.computeIfAbsent(username, k -> new CopyOnWriteArrayList<>()).add(emitter);

	        emitter.onCompletion(() -> removeEmitter(username, emitter));
	        emitter.onTimeout(()    -> removeEmitter(username, emitter));
	        emitter.onError(e       -> removeEmitter(username, emitter));

	        log.info("SSE emitter created for user: {}", username);
	        return emitter;
	    }

	    public void sendEvent(String username, Object payload) {
	        List<SseEmitter> userEmitters = emitters.get(username);
	        if (userEmitters == null) return;

	        for (SseEmitter emitter : userEmitters) {
	            try {
	                emitter.send(SseEmitter.event().name("new-message").data(payload));
	            } catch (IOException e) {
	                log.warn("Failed to send SSE to {}, removing emitter", username, e);
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
	

