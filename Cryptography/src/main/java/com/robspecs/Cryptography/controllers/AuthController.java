package com.robspecs.Cryptography.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.Enums.Roles;
import com.robspecs.Cryptography.dto.RegistrationDTO;
import com.robspecs.Cryptography.exceptions.JWTTokenNotFoundException;
import com.robspecs.Cryptography.exceptions.TokenNotFoundException;
import com.robspecs.Cryptography.service.AuthService;
import com.robspecs.Cryptography.service.TokenBlacklistService;


import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final AuthService authService;

	private final StringRedisTemplate redisTemplate;
	private final TokenBlacklistService tokenService;

	@Autowired
	public AuthController(AuthService authService, StringRedisTemplate redisTemplate,
			TokenBlacklistService tokenService) {
		this.authService = authService;
		this.redisTemplate = redisTemplate;
		this.tokenService = tokenService;

	}

	@PostMapping({ "/register", "/signup" })
	public ResponseEntity<?> signup(@RequestBody RegistrationDTO currDTO) {
	    String otpVerified = redisTemplate.opsForValue().get(currDTO.getEmail());

	    if (!"1".equals(otpVerified)) {
	        return new ResponseEntity<>("EMAIL IS NOT VERIFIED, REGISTER AGAIN", HttpStatus.BAD_REQUEST);
	    }

	    authService.registerNewUser(currDTO);
	    return ResponseEntity.ok("User registered successfully!");
	}

	// APIS FOR VLAIDATIONG HTE TOKEN
	@GetMapping("/validate")
	public String validateToken() {
		return "Token is valid ✅";
	}

	
	
	@PostMapping("/logout")
	public ResponseEntity<?> logoutUser(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws RuntimeException {
		// Pass authentication object if needed by the service layer
		try {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			if (auth != null) {
				String[] tokens = getRefreshAndAcessToken(request);
				tokenService.blacklistToken(tokens[0], 300);
				tokenService.blacklistToken(tokens[1], 30);
				SecurityContextHolder.clearContext();
				
				Cookie expiredCookie = new Cookie("refreshToken", null);
				expiredCookie.setMaxAge(0);
				expiredCookie.setHttpOnly(true);
				expiredCookie.setPath("/");
				response.addCookie(expiredCookie);
			}
			return ResponseEntity.ok("User logged out successfully.");
		} catch (RuntimeException e) {
			return ResponseEntity.internalServerError().body("LOGOUT UNSUCESSFUL, SOME ERROR OCCURS" + e.getLocalizedMessage());

		}
	}

	String[] getRefreshAndAcessToken(HttpServletRequest request) throws JWTTokenNotFoundException {

		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			throw new JWTTokenNotFoundException("Cookie is Empty!");
		}
		String refreshToken = null;
		for (Cookie cookie : cookies) {
			if ("refreshToken".equals(cookie.getName())) {
				refreshToken = cookie.getValue();
				 break; 
			}
		}
		if (refreshToken == null) {
			throw new JWTTokenNotFoundException("Refresh Token is Invalid or not present");
		}
		String accessToken = extractTokenFromRequest(request);
		return new String[] { refreshToken, accessToken };
	}

	private String extractTokenFromRequest(HttpServletRequest request) throws TokenNotFoundException {
		String bearerToken = request.getHeader("Authorization");
		if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7);
		}
		throw new TokenNotFoundException(request.getLocalName() + " request doesn't contain token");
	}

}
