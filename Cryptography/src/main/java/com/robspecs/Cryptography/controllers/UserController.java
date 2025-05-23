package com.robspecs.Cryptography.controllers;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.UserDTO;
import com.robspecs.Cryptography.service.UserService;

@RestController
@RequestMapping("/api/users")
public class UserController {

	private final UserService userService;

	public UserController(UserService userService) {
		super();
		this.userService = userService;
	}

	@GetMapping("/all")
	public ResponseEntity<List<UserDTO>> getAllUsers(@AuthenticationPrincipal User currentUser) {
		List<UserDTO> users = userService.getAllUsers(currentUser);
		return ResponseEntity.ok(users);
	}

}
