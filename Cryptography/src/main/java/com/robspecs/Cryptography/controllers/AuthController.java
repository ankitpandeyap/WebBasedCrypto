package com.robspecs.Cryptography.controllers;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.robspecs.Cryptography.dto.RegistrationDTO;
import com.robspecs.Cryptography.exceptions.EncryptionDecryptionException;
import com.robspecs.Cryptography.exceptions.JWTTokenNotFoundException;
import com.robspecs.Cryptography.exceptions.TokenNotFoundException;
//New imports for custom exceptions
import com.robspecs.Cryptography.exceptions.UserAlreadyExistsException;
import com.robspecs.Cryptography.service.AuthService;
import com.robspecs.Cryptography.service.PasskeyCacheService; // Added import for PasskeyCacheService
import com.robspecs.Cryptography.service.TokenBlacklistService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final AuthService authService;
	private final StringRedisTemplate redisTemplate;
	private final TokenBlacklistService tokenService;
	private final PasskeyCacheService passkeyCacheService;
	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

	@Autowired
	public AuthController(AuthService authService, StringRedisTemplate redisTemplate,
			TokenBlacklistService tokenService, PasskeyCacheService passkeyCacheService) {
		this.authService = authService;
		this.redisTemplate = redisTemplate;
		this.tokenService = tokenService;
		this.passkeyCacheService = passkeyCacheService;
		logger.debug("AuthController initialized");
	}

	@PostMapping({ "/register", "/signup" })
	public ResponseEntity<?> signup(@Valid @RequestBody RegistrationDTO currDTO) {
		logger.info("Received signup request for email: {}", currDTO.getEmail());
		String verifiedFlagKey = currDTO.getEmail() + ":verified";
		String otpVerified = redisTemplate.opsForValue().get(verifiedFlagKey);
		logger.debug("Checking OTP verification status for key: {}", verifiedFlagKey);

		if (!"true".equals(otpVerified)) {
			logger.warn("Email {} not verified via OTP", currDTO.getEmail());
			return new ResponseEntity<>(
					"Email has not been verified via OTP or verification expired. Please request and verify OTP again.",
					HttpStatus.BAD_REQUEST);
		}

		try {
			authService.registerNewUser(currDTO);
			logger.info("User registered successfully: {}", currDTO.getEmail());

			redisTemplate.delete(verifiedFlagKey);
			logger.debug("OTP verification flag deleted for key: {}", verifiedFlagKey);

			return ResponseEntity.ok("User registered successfully!");
		} catch (UserAlreadyExistsException e) {
			logger.warn("Registration failed for email {}: {}", currDTO.getEmail(), e.getMessage());
			// @ResponseStatus(HttpStatus.CONFLICT) on UserAlreadyExistsException handles
			// status
			return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
		} catch (EncryptionDecryptionException e) {
			logger.error("Error during encryption key setup for email {}: {}", currDTO.getEmail(), e.getMessage(), e);
			// @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR) on
			// EncryptionDecryptionException handles status
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("Registration failed due to encryption setup: " + e.getMessage());
		} catch (Exception e) { // Catch any other unexpected exceptions
			logger.error("Unexpected error during registration for email {}: {}", currDTO.getEmail(), e.getMessage(),
					e);
			return ResponseEntity.internalServerError().body("Registration failed: An unexpected error occurred.");
		}
	}

	@GetMapping("/validate")
	public String validateToken() {
		logger.info("Received /validate request. Returning success.");
		return "Token is valid ✅";
	}

	@PostMapping("/logout")
	public ResponseEntity<?> logoutUser(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) { 
		logger.info("Received logout request");
		try {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			String username = (auth != null && auth.getName() != null) ? auth.getName() : "unknown";
			logger.debug("Processing logout for user: {}", username);

			// --- CHANGED: Use the modified helper methods that return null instead of
		
			String[] tokens = getRefreshAndAccessToken(request); 
			String refreshToken = tokens[0];
			String accessToken = tokens[1];

			if (refreshToken != null) {
				tokenService.blacklistToken(refreshToken, 300); // Blacklist for 5 min (or refresh token maxAge)
				logger.debug("Refresh token blacklisted: {}",
						refreshToken.substring(0, Math.min(refreshToken.length(), 10)) + "...");
			} else {
				logger.warn("Refresh token not found in logout request for user: {}. Cannot blacklist.", username);
			}

			// Also check for "null" string for access token (from frontend sending "Bearer
			// null")
			if (accessToken != null && !accessToken.equals("null")) {
				tokenService.blacklistToken(accessToken, 30); // Blacklist for 30 minute (access token maxAge)
				logger.debug("Access token blacklisted: {}",
						accessToken.substring(0, Math.min(accessToken.length(), 10)) + "...");
			} else {
				logger.warn(
						"Access token not found or was 'null' string in logout request for user: {}. Cannot blacklist.",
						username);
			}

			if (auth != null && auth.getName() != null) {
				passkeyCacheService.clearValidated(auth.getName());
				logger.debug("Passkey cache cleared for user: {}", auth.getName());
				SecurityContextHolder.clearContext();
				logger.debug("Security Context cleared for user: {}", auth.getName());
			} else {
				logger.warn(
						"SecurityContext not available or user name null during logout cleanup. Passkey cache not cleared.");
			}

			// --- CHANGED: Always attempt to expire the cookie ---
			Cookie expiredCookie = new Cookie("refreshToken", null);
			expiredCookie.setMaxAge(0); // Expires immediately
			expiredCookie.setHttpOnly(true);
			expiredCookie.setPath("/"); // Crucial for clearing the correct cookie
			// For production, ensure this is `true` if your frontend is HTTPS
			// expiredCookie.setSecure(true);
			response.addCookie(expiredCookie);
			logger.debug("Refresh token cookie expired for user: {}", username);

			return ResponseEntity.ok("User logged out successfully.");
		} catch (Exception e) { // Catch all general exceptions for robust error handling
			logger.error("Unexpected error during logout for user {}: {}",
					SecurityContextHolder.getContext().getAuthentication() != null
							? SecurityContextHolder.getContext().getAuthentication().getName()
							: "unknown",
					e.getMessage(), e);
			return ResponseEntity.internalServerError().body("Logout unsuccessful: An unexpected error occurred.");
		}
	}

	// --- CHANGED: Modified to return null instead of throwing exceptions ---
	String[] getRefreshAndAccessToken(HttpServletRequest request) { // Removed throws JWTTokenNotFoundException
		logger.debug("Attempting to extract refresh and access tokens from request");
		Cookie[] cookies = request.getCookies();
		String refreshToken = null;
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if ("refreshToken".equals(cookie.getName())) {
					refreshToken = cookie.getValue();
					logger.debug("Refresh token found in cookie.");
					break;
				}
			}
		}
		if (refreshToken == null) {
			logger.warn("Refresh Token is missing or not present in cookies.");
		}
		String accessToken = extractAccessTokenFromRequest(request); // Use the new method
		logger.debug("Access token extracted: {}", accessToken != null ? "present" : "null");
		return new String[] { refreshToken, accessToken };
	}

	// --- CHANGED: Modified to return null instead of throwing exceptions ---
	private String extractAccessTokenFromRequest(HttpServletRequest request) { // Renamed for clarity, removed throws
																				// TokenNotFoundException
		logger.debug("Attempting to extract access token from Authorization header");
		String bearerToken = request.getHeader("Authorization");
		if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
			String token = bearerToken.substring(7);
			logger.debug("Access token found in Authorization header.");
			return token;
		}
		logger.warn("Authorization header with Bearer token is missing or malformed (expected 'Bearer <token>').");
		return null; // Return null instead of throwing
	}

	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public Map<String, String> handleValidationExceptions(MethodArgumentNotValidException ex) {
		Map<String, String> errors = new HashMap<>();
		ex.getBindingResult().getAllErrors().forEach((error) -> {
			String fieldName = ((FieldError) error).getField();
			String errorMessage = error.getDefaultMessage();
			errors.put(fieldName, errorMessage);
		});
		logger.warn("Validation errors in AuthController: {}", errors);
		return errors;
	}
}