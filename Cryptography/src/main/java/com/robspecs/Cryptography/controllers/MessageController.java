package com.robspecs.Cryptography.controllers;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import com.robspecs.Cryptography.Entities.User;

import com.robspecs.Cryptography.dto.MessageRequestDTO;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;
import com.robspecs.Cryptography.service.MessageService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/messages")
public class MessageController {

	private final MessageService messageService;

	public MessageController(MessageService messageService) {
		super();
		this.messageService = messageService;
	}

	@PostMapping("/send")
	public ResponseEntity<?> send(@Valid @RequestBody MessageRequestDTO request,
			@AuthenticationPrincipal User currentUser) throws Exception {
		try {
			messageService.sendMessage(request, currentUser.getUserName());
			return ResponseEntity.ok().body("Message Sent Sucessfully");
		} catch (Exception e) {
			return ResponseEntity.internalServerError().body(e.getLocalizedMessage());
		}
	}

	@GetMapping("/inbox")
	public ResponseEntity<?> listInbox(@AuthenticationPrincipal User currentUser) {
		try {
			List<MessageSummaryDTO> inbox = messageService.getInboxMessages(currentUser);
			return ResponseEntity.ok(inbox);
		} catch (RuntimeException e) {
			return ResponseEntity.status(500).body("Failed to load inbox messages: " + e.getMessage());
		}
	}

}