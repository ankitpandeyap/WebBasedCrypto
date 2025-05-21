package com.robspecs.Cryptography.controllers;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.MessageRequestDTO;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;
import com.robspecs.Cryptography.service.MessageService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/messages")
public class MessageController {

	// --- START: Manual Logger Instance ---
	private static final Logger log = LoggerFactory.getLogger(MessageController.class);
	// --- END: Manual Logger Instance ---

	private final MessageService messageService;

	public MessageController(MessageService messageService) {
		// super(); // Can be removed, it's redundant
		this.messageService = messageService;
		log.info("MessageController initialized."); // Log controller initialization
	}

	@PostMapping("/send")
	public ResponseEntity<?> send(@Valid @RequestBody MessageRequestDTO request,
			@AuthenticationPrincipal User currentUser) throws Exception {
		log.info("Received send message request from user: {} to receiver: {}", currentUser.getUserName(),
				request.getToUsername());
		try {
			messageService.sendMessage(request, currentUser.getUserName());
			log.info("Message sent successfully from {} to {}", currentUser.getUserName(), request.getToUsername());
			return ResponseEntity.ok().body("Message Sent Sucessfully");
		} catch (Exception e) {
			log.error("Failed to send message from {} to {}: {}", currentUser.getUserName(), request.getToUsername(),
					e.getLocalizedMessage(), e);
			return ResponseEntity.internalServerError().body(e.getLocalizedMessage());
		}
	}

	@GetMapping("/inbox")
	public ResponseEntity<?> listInbox(@AuthenticationPrincipal User currentUser) {
		log.info("Received inbox request for user: {}", currentUser.getUserName());
		try {
			List<MessageSummaryDTO> inbox = messageService.getInboxMessages(currentUser);
			log.info("Successfully fetched inbox messages for user: {}. Count: {}", currentUser.getUserName(),
					inbox.size());
			return ResponseEntity.ok(inbox);
		} catch (RuntimeException e) {
			log.error("Failed to load inbox messages for user {}: {}", currentUser.getUserName(), e.getMessage(), e);
			return ResponseEntity.status(500).body("Failed to load inbox messages: " + e.getMessage());
		}
	}

	@PostMapping("/{id}/decrypt")
	public ResponseEntity<?> decrypt(@PathVariable("id") Long messageId, @RequestBody Map<String, String> body,
			@AuthenticationPrincipal User currentUser) {

		String passkey = body.get("passkey"); // Note: passkey is sensitive, avoid logging its value

		// --- START: Added Passkey validation and logging ---
		if (passkey == null || passkey.trim().isEmpty()) {
			log.warn("Decrypt request for message ID {} from user {} received with missing or empty passkey.",
					messageId, currentUser.getUserName());
			return ResponseEntity.badRequest().body("Passkey is required.");
		}
		log.info("Received decrypt request for message ID {} from user: {}", messageId, currentUser.getUserName());
		// --- END: Added Passkey validation and logging ---

		try {
			String plainText = messageService.decryptMessage(messageId, currentUser, passkey);
			log.info("Message ID {} successfully decrypted for user {}.", messageId, currentUser.getUserName());
			return ResponseEntity.ok(Map.of("plainText", plainText));
		} catch (RuntimeException e) { // This will catch NotFoundException, UnauthorizedException,
										// AccessDeniedException if they are RuntimeExceptions
			// Consider logging specific custom exceptions if you want to differentiate
			log.warn("Decrypt failed for messageId={}: {}. User: {}", messageId, e.getMessage(),
					currentUser.getUserName());
			// This is a broad catch, the message itself from e.getMessage() could reveal
			// details.
			// If you want more specific HTTP statuses (401, 403, 404), you'd need more
			// specific catches like in the previous example.
			return ResponseEntity.status(HttpStatus.FORBIDDEN) // A general "Forbidden" for RuntimeExceptions
					.body(e.getMessage());
		} catch (Exception e) {
			log.error("Unexpected error during decrypt for messageId={}: {}", messageId, e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Decryption error");
		}
	}

	@PostMapping("/{id}/verify-passkey")
	public ResponseEntity<?> verifyPasskey(@PathVariable("id") Long messageId, @RequestBody Map<String, String> body,
			@AuthenticationPrincipal User currentUser) {

		String passkey = body.get("passkey");
		try {
			String decryptionKey = messageService.verifyPasskeyAndGetKey(messageId, currentUser, passkey);
			return ResponseEntity.ok(Map.of("decryptionKey", decryptionKey));
		} catch (RuntimeException e) {
			log.warn("Passkey verification failed for msg={}: {}", messageId, e.getMessage());
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
		} catch (Exception e) {
			log.error("Unexpected error verifying passkey for msg={}: {}", messageId, e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Verification error");
		}
	}

}