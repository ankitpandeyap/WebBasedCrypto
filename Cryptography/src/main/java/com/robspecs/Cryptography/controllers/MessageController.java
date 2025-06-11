package com.robspecs.Cryptography.controllers;

import java.io.IOException; // Keep for potential local IOException if needed
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.Enums.Algorithm;
import com.robspecs.Cryptography.dto.MessageRequestDTO;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;
import com.robspecs.Cryptography.dto.FileDownloadResponseDTO; // NEW IMPORT: Import your new DTO
import com.robspecs.Cryptography.service.MessageService;
import com.robspecs.Cryptography.service.PasskeyCacheService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

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
			@AuthenticationPrincipal User currentUser) throws Exception { // Propagate exceptions
		logger.info("Received send text message request from user: {}", currentUser.getUserName());

		// --- Explicit validation for text messages (immediate 400 response) ---
		if (messageRequest.getFile() != null && !messageRequest.getFile().isEmpty()) {
			logger.warn("Attempted to send file via text message endpoint from user: {}", currentUser.getUserName());
			return ResponseEntity.badRequest().body(Map.of("error", "Please use /api/messages/send-file for file uploads."));
		}
		if (messageRequest.getRawMessage() == null || messageRequest.getRawMessage().isBlank()) {
			logger.warn("Text message content is empty for user: {}", currentUser.getUserName());
			return ResponseEntity.badRequest().body(Map.of("error", "Text message content cannot be empty."));
		}
		// --- End Validation ---

		messageService.sendMessage(messageRequest, currentUser.getUserName());
		logger.info("Text message sent successfully by user: {}", currentUser.getUserName());
		return ResponseEntity.ok("Message sent successfully!");
	}

	@PostMapping(value = "/send-file", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<?> sendFile(
			@RequestPart("file") MultipartFile file,
			@RequestParam("toUsername") @NotBlank String toUsername,
			@RequestParam("algorithm") @NotNull Algorithm algorithm,
			@AuthenticationPrincipal User currentUser) throws Exception { // Propagate exceptions

		logger.info("Received send file request from user: {}", currentUser.getUserName());

		// --- Explicit validation for file messages (immediate 400 response) ---
		if (file == null || file.isEmpty()) {
			logger.warn("Attempted to send empty file from user: {}", currentUser.getUserName());
			return ResponseEntity.badRequest().body(Map.of("error", "File content cannot be empty."));
		}
		// Assuming rawMessage is not sent for file uploads as per the controller construction.
		// If it were, validation like: if (StringUtils.hasText(rawMessage)) return badRequest; would be needed.
		// Service layer does this validation robustly as well.
		// --- End Validation ---

		MessageRequestDTO messageRequest = new MessageRequestDTO();
		messageRequest.setToUsername(toUsername);
		messageRequest.setFile(file);
		messageRequest.setAlgorithm(algorithm);
		messageRequest.setRawMessage(null); // Ensure rawMessage is null for file uploads

		messageService.sendFile(messageRequest, currentUser.getUserName());
		logger.info("File sent successfully by user: {}", currentUser.getUserName());
		return ResponseEntity.ok("File sent successfully!");
	}

	@GetMapping("/inbox")
	public ResponseEntity<List<MessageSummaryDTO>> getInboxMessages(@AuthenticationPrincipal User currentUser) {
		logger.info("Received inbox request for user: {}", currentUser.getUserName());
		List<MessageSummaryDTO> messages = messageService.getInboxMessages(currentUser); // Exceptions handled globally
		logger.info("Retrieved {} messages for user: {}", messages.size(), currentUser.getUserName());
		return ResponseEntity.ok(messages);
	}

	@PostMapping("/{messageId}/decrypt")
	public ResponseEntity<Map<String, String>> decryptMessage(@PathVariable Long messageId,
			@RequestParam String passkey, @AuthenticationPrincipal User currentUser) throws Exception { // Propagate exceptions
		logger.info("Received decrypt text message request for message ID: {} by user: {}", messageId, currentUser.getUserName());

		// Service layer will throw IllegalArgumentException if it's a file message, which GlobalExceptionHandler will catch.
		String decryptedContent = messageService.decryptMessage(messageId, currentUser, passkey);
		logger.info("Message ID: {} decrypted successfully for user: {}", messageId, currentUser.getUserName());

		Map<String, String> response = new HashMap<>();
		response.put("decryptedContent", decryptedContent);
		return ResponseEntity.ok(response);
	}

	@GetMapping("/{messageId}/download")
	public ResponseEntity<ByteArrayResource> downloadFile(@PathVariable Long messageId,
														  @RequestParam String passkey,
														  @AuthenticationPrincipal User currentUser) throws Exception { // Propagate exceptions
		logger.info("Received download file request for message ID: {} by user: {}", messageId, currentUser.getUserName());

        // --- UPDATED: Call service and get FileDownloadResponseDTO ---
		FileDownloadResponseDTO downloadResponse = messageService.downloadFile(messageId, currentUser, passkey);
		logger.info("File ID: {} decrypted and retrieved successfully for user: {}", messageId, currentUser.getUserName());

        // --- Extract data from the DTO ---
		ByteArrayResource resource = downloadResponse.getResource();
		String filename = downloadResponse.getFileName();
		String contentType = downloadResponse.getContentType();
        // --- END UPDATED ---

		return ResponseEntity.ok()
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
				.contentType(MediaType.parseMediaType(contentType))
				.contentLength(resource.contentLength())
				.body(resource);
	}

	@PostMapping("/{messageId}/verify-passkey")
	public ResponseEntity<String> verifyPasskey(@PathVariable Long messageId, @RequestParam String passkey,
			@AuthenticationPrincipal User currentUser) throws Exception { // Propagate exceptions
		logger.info("Received verify passkey request for message ID: {} by user: {}", messageId, currentUser.getUserName());
		String messageContentKey = messageService.verifyPasskeyAndGetKey(messageId, currentUser, passkey);
		logger.info("Passkey verified successfully for message ID: {} by user: {}. Message content key retrieved.",
				messageId, currentUser.getUserName());
		// Return a success status or a specific DTO, not the raw key for security in production.
		// For consistency, let's return a success message.
		return ResponseEntity.ok("Passkey verified successfully!");
	}

	@GetMapping("/sent")
	public ResponseEntity<List<MessageSummaryDTO>> getSentMessages(@AuthenticationPrincipal User currentUser) {
		logger.info("Received sent messages request for user: {}", currentUser.getUserName());
		List<MessageSummaryDTO> messages = messageService.getSentMessages(currentUser); // Exceptions handled globally
		logger.info("Retrieved {} sent messages for user: {}", messages.size(), currentUser.getUserName());
		return ResponseEntity.ok(messages);
	}

	@PatchMapping("/{messageId}/read")
	public ResponseEntity<String> markMessageAsRead(@PathVariable Long messageId,
			@AuthenticationPrincipal User currentUser) { // Exceptions handled globally
		logger.info("Received mark as read request for message ID: {} by user: {}", messageId, currentUser.getUserName());
		messageService.markMessageAsRead(messageId, currentUser.getUserName());
		logger.info("Message ID: {} marked as read successfully for user: {}", messageId, currentUser.getUserName());
		return ResponseEntity.ok("Message marked as read successfully!");
	}

	@PatchMapping("/{messageId}/star")
	public ResponseEntity<String> toggleMessageStarred(@PathVariable Long messageId,
			@AuthenticationPrincipal User currentUser) { // Exceptions handled globally
		logger.info("Received toggle star request for message ID: {} by user: {}", messageId, currentUser.getUserName());
		messageService.toggleMessageStarred(messageId, currentUser.getUserName());
		logger.info("Message ID: {} starred status toggled successfully for user: {}", messageId, currentUser.getUserName());
		return ResponseEntity.ok("Message starred status toggled successfully!");
	}

	@DeleteMapping("/{messageId}")
	public ResponseEntity<String> deleteMessage(@PathVariable Long messageId,
			@AuthenticationPrincipal User currentUser) { // Exceptions handled globally
		logger.info("Received delete request for message ID: {} by user: {}", messageId, currentUser.getUserName());
		messageService.deleteMessage(messageId, currentUser.getUserName());
		logger.info("Message ID: {} hard deleted successfully by user: {}", messageId, currentUser.getUserName());
		return ResponseEntity.ok("Message deleted successfully!");
	}

}