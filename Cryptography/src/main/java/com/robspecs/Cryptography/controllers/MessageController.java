package com.robspecs.Cryptography.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import com.robspecs.Cryptography.Entities.User;

import com.robspecs.Cryptography.dto.MessageRequestDTO;
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

		messageService.sendMessage(request, currentUser.getUserName());
		return ResponseEntity.ok().build();
	}
}
