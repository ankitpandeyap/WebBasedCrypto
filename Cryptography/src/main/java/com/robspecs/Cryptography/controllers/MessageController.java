package com.robspecs.Cryptography.controllers;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.MessageRequestDTO;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;
import com.robspecs.Cryptography.service.MessageService;
import com.robspecs.Cryptography.service.PasskeyCacheService;

import jakarta.validation.Valid;

import com.robspecs.Cryptography.exceptions.NotFoundException;
import com.robspecs.Cryptography.exceptions.UnauthorizedException;
import com.robspecs.Cryptography.exceptions.InvalidPasskeyException;
import com.robspecs.Cryptography.exceptions.MissingEncryptionKeyException;
import com.robspecs.Cryptography.exceptions.EncryptionDecryptionException;

@RestController
@RequestMapping("/api/messages")
public class MessageController {

	private final MessageService messageService;
	private final PasskeyCacheService passkeyCacheService;
	private static final Logger logger = LoggerFactory.getLogger(MessageController.class);

	@Autowired
	public MessageController(MessageService messageService, PasskeyCacheService passkeyCacheService) {
		this.messageService = messageService;
		this.passkeyCacheService = passkeyCacheService;
		logger.debug("MessageController initialized.");
	}

	@PostMapping("/send")
	public ResponseEntity<?> sendMessage(@Valid @RequestBody MessageRequestDTO messageRequest,
			@AuthenticationPrincipal User currentUser) {
		logger.info("Received send message request from user: {}", currentUser.getUserName());
		try {
			messageService.sendMessage(messageRequest, currentUser.getUserName());
			logger.info("Message sent successfully by user: {}", currentUser.getUserName());
			return ResponseEntity.ok("Message sent successfully!");
		} catch (NotFoundException e) { // For sender/receiver not found
			logger.warn("Failed to send message from {} due to user not found: {}", currentUser.getUserName(),
					e.getMessage());
			// @ResponseStatus(HttpStatus.NOT_FOUND) on NotFoundException handles status
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
		} catch (MissingEncryptionKeyException e) { // For receiver missing derived key
			logger.error("Failed to send message from {} due to receiver missing encryption key: {}",
					currentUser.getUserName(), e.getMessage(), e);
			// @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR) on
			// MissingEncryptionKeyException handles status
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("Failed to send message: " + e.getMessage());
		} catch (EncryptionDecryptionException e) { // For encryption failures during message or key encryption
			logger.error("Failed to send message from {} due to encryption error: {}", currentUser.getUserName(),
					e.getMessage(), e);
			// @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR) on
			// EncryptionDecryptionException handles status
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("Failed to send message: " + e.getMessage());
		} catch (Exception e) { // Catch any other unexpected exceptions
			logger.error("Unexpected error during send message from {}: {}", currentUser.getUserName(), e.getMessage(),
					e);
			return ResponseEntity.internalServerError().body("Failed to send message: An unexpected error occurred.");
		}
	}

	@GetMapping("/inbox")
	public ResponseEntity<List<MessageSummaryDTO>> getInboxMessages(@AuthenticationPrincipal User currentUser) {
		logger.info("Received inbox request for user: {}", currentUser.getUserName());
		try {
			List<MessageSummaryDTO> messages = messageService.getInboxMessages(currentUser);
			logger.info("Retrieved {} messages for user: {}", messages.size(), currentUser.getUserName());
			return ResponseEntity.ok(messages);
		} catch (Exception e) { // For now, keeping generic catch as MessageServiceImpl throws RuntimeException
			logger.error("Failed to retrieve inbox for user {}: {}", currentUser.getUserName(), e.getMessage(), e);
			return ResponseEntity.internalServerError().body(null); // Return null body for 500, or a specific error DTO
		}
	}

	@PostMapping("/{messageId}/decrypt")
	public ResponseEntity<Map<String, String>> decryptMessage(@PathVariable Long messageId,
			@RequestParam String passkey, @AuthenticationPrincipal User currentUser) {
		logger.info("Received decrypt request for message ID: {} by user: {}", messageId, currentUser.getUserName());
		try {
			String decryptedContent = messageService.decryptMessage(messageId, currentUser, passkey);
			logger.info("Message ID: {} decrypted successfully for user: {}", messageId, currentUser.getUserName());

			Map<String, String> response = new HashMap<>();
			response.put("decryptedContent", decryptedContent);
			return ResponseEntity.ok(response);
		} catch (NotFoundException e) {
			logger.warn("Decryption failed for message ID: {} (user: {}) - Not found: {}", messageId,
					currentUser.getUserName(), e.getMessage());
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
		} catch (UnauthorizedException | InvalidPasskeyException e) {
			logger.warn("Decryption failed for message ID: {} (user: {}) - Unauthorized: {}", messageId,
					currentUser.getUserName(), e.getMessage());
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", e.getMessage()));
		} catch (MissingEncryptionKeyException | EncryptionDecryptionException e) {
			logger.error("Decryption failed for message ID: {} (user: {}) - Encryption error: {}", messageId,
					currentUser.getUserName(), e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", e.getMessage()));
		} catch (Exception e) {
			logger.error("Unexpected error during decrypt message ID: {} for user {}: {}", messageId,
					currentUser.getUserName(), e.getMessage(), e);
			return ResponseEntity.internalServerError()
					.body(Map.of("error", "Decryption failed: An unexpected error occurred."));
		}
	}

	@PostMapping("/{messageId}/verify-passkey")
	public ResponseEntity<String> verifyPasskey(@PathVariable Long messageId, @RequestParam String passkey,
			@AuthenticationPrincipal User currentUser) {
		logger.info("Received verify passkey request for message ID: {} by user: {}", messageId,
				currentUser.getUserName());
		try {
			String messageContentKey = messageService.verifyPasskeyAndGetKey(messageId, currentUser, passkey);
			logger.info("Passkey verified successfully for message ID: {} by user: {}. Message content key retrieved.",
					messageId, currentUser.getUserName());
			// You might not want to return the actual messageContentKey to the client in a
			// real app,
			// but rather a success status (e.g., 200 OK with a boolean true).
			// For now, returning it as per existing method signature.
			return ResponseEntity.ok(messageContentKey);
		} catch (NotFoundException e) { // Message or DecryptionKey not found
			logger.warn("Passkey verification failed for message ID: {} (user: {}) - Not found: {}", messageId,
					currentUser.getUserName(), e.getMessage());
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
		} catch (UnauthorizedException e) { // User is not the receiver
			logger.warn("Passkey verification failed for message ID: {} (user: {}) - Unauthorized: {}", messageId,
					currentUser.getUserName(), e.getMessage());
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
		} catch (MissingEncryptionKeyException e) { // User's account missing key components
			logger.error("Passkey verification failed for message ID: {} (user: {}) - Missing encryption key: {}",
					messageId, currentUser.getUserName(), e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
		} catch (InvalidPasskeyException e) { // Incorrect passkey
			logger.warn("Passkey verification failed for message ID: {} (user: {}) - Invalid passkey: {}", messageId,
					currentUser.getUserName(), e.getMessage());
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
		} catch (EncryptionDecryptionException e) { // General crypto failure during verification
			logger.error("Passkey verification failed for message ID: {} (user: {}) - Encryption/Decryption error: {}",
					messageId, currentUser.getUserName(), e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
		} catch (Exception e) { // Catch any other unexpected exceptions
			logger.error("Unexpected error during passkey verification for message ID: {} for user {}: {}", messageId,
					currentUser.getUserName(), e.getMessage(), e);
			return ResponseEntity.internalServerError()
					.body("Passkey verification failed: An unexpected error occurred.");
		}
	}
}