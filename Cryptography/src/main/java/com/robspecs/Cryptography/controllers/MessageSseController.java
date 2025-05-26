package com.robspecs.Cryptography.controllers;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.service.SseEmitterService;

@RestController
@RequestMapping("/api/messages")
public class MessageSseController {
	private static final Logger log = LoggerFactory.getLogger(MessageSseController.class);
	private final SseEmitterService sseEmitterService;

	public MessageSseController(SseEmitterService sseEmitterService) {
		super();
		this.sseEmitterService = sseEmitterService;
		log.info("MessageSseController initialized.");
	}

	@GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
	  public SseEmitter streamMessages(@AuthenticationPrincipal User currentUser) throws IOException {
        log.info("Received SSE stream request for user: {}", currentUser.getUserName()); // Log request received

        // Returns an emitter; SSE connection stays open indefinitely
        SseEmitter emitter = sseEmitterService.createEmitter(currentUser.getUserName());
        log.debug("SSE emitter created and returned for user: {}", currentUser.getUserName()); // Log emitter creation

        return emitter;
    }

	   @ExceptionHandler(IOException.class)
	    public ResponseEntity<String> handleIOException(IOException ex) {
	        log.error("IOException during SSE stream creation for user: {}", ex.getMessage());
	        // Return a 500 Internal Server Error or other appropriate status
	        return new ResponseEntity<>("Failed to establish SSE connection: " + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
	    }
}
