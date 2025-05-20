package com.robspecs.Cryptography.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private final StringRedisTemplate redisTemplate; // Injected to check email verification status
    private final TokenBlacklistService tokenService;
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    public AuthController(AuthService authService, StringRedisTemplate redisTemplate,
            TokenBlacklistService tokenService) {
        this.authService = authService;
        this.redisTemplate = redisTemplate;
        this.tokenService = tokenService;
        logger.debug("AuthController initialized");
    }

    @PostMapping({ "/register", "/signup" })
    public ResponseEntity<?> signup(@RequestBody RegistrationDTO currDTO) {
        logger.info("Received signup request for email: {}", currDTO.getEmail());
        String verifiedFlagKey = currDTO.getEmail() + ":verified";
        String otpVerified = redisTemplate.opsForValue().get(verifiedFlagKey); // Check the new key
        logger.debug("Checking OTP verification status for key: {}", verifiedFlagKey);

        // Check if the email has been successfully verified via OTP
        if (!"true".equals(otpVerified)) { // Expect "true" as the value
            logger.warn("Email {} not verified via OTP", currDTO.getEmail());
            return new ResponseEntity<>("Email has not been verified via OTP or verification expired. Please request and verify OTP again.", HttpStatus.BAD_REQUEST);
        }

        // If OTP is verified, proceed with user registration
        try {
            authService.registerNewUser(currDTO);
            logger.info("User registered successfully: {}", currDTO.getEmail());

            // IMPORTANT: Clean up the verification flag after successful registration
            redisTemplate.delete(verifiedFlagKey);
            logger.debug("OTP verification flag deleted for key: {}", verifiedFlagKey);

            return ResponseEntity.ok("User registered successfully!");
        } catch (Exception e) {
            logger.error("Error during registration for email {}: {}", currDTO.getEmail(), e.getMessage());
            return ResponseEntity.internalServerError().body("Registration failed: " + e.getMessage()); // Return the original exception message
        }
    }

    // APIS FOR VALIDATING THE TOKEN
    @GetMapping("/validate")
    public String validateToken() {
        logger.info("Received /validate request.  Returning success.");
        return "Token is valid ✅";
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws RuntimeException {
        logger.info("Received logout request");
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null) {
                logger.debug("User is authenticated.  Processing logout.");
                String[] tokens = getRefreshAndAcessToken(request);
                String refreshToken = tokens[0];
                String accessToken = tokens[1];
                // Blacklist refresh token (e.g., 5 minutes or until it expires)
                tokenService.blacklistToken(refreshToken, 300);
                logger.debug("Refresh token blacklisted: {}", refreshToken);
                // Blacklist access token (e.g., 30 seconds or until it expires)
                tokenService.blacklistToken(accessToken, 30);
                logger.debug("Access token blacklisted: {}", accessToken);
                SecurityContextHolder.clearContext();
                logger.debug("Security Context cleared");

                // Expire refresh token cookie in the browser
                Cookie expiredCookie = new Cookie("refreshToken", null);
                expiredCookie.setMaxAge(0); // Set max age to 0 to delete the cookie
                expiredCookie.setHttpOnly(true); // Should be HttpOnly for security
                expiredCookie.setPath("/"); // Ensure path matches the original cookie path
                response.addCookie(expiredCookie);
                logger.debug("Refresh token cookie expired");
            } else {
                logger.warn("Logout called for unauthenticated user.");
            }
            return ResponseEntity.ok("User logged out successfully.");
        } catch (RuntimeException e) {
            logger.error("Error during logout: {}", e.getMessage());
            // Catch specific exceptions like JWTTokenNotFoundException for more tailored responses
            if (e instanceof JWTTokenNotFoundException || e instanceof TokenNotFoundException) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Logout failed: " + e.getMessage());
            }
            return ResponseEntity.internalServerError().body("Logout unsuccessful: " + e.getLocalizedMessage());
        }
    }

    String[] getRefreshAndAcessToken(HttpServletRequest request) throws JWTTokenNotFoundException {
        logger.debug("Extracting refresh and access tokens from request");
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            logger.warn("No cookies found in request.");
            throw new JWTTokenNotFoundException("No cookies found in request.");
        }
        String refreshToken = null;
        for (Cookie cookie : cookies) {
            if ("refreshToken".equals(cookie.getName())) {
                refreshToken = cookie.getValue();
                logger.debug("Refresh token found in cookie: {}", refreshToken);
                break;
            }
        }
        if (refreshToken == null) {
            logger.warn("Refresh Token is missing or not present in cookies.");
            throw new JWTTokenNotFoundException("Refresh Token is missing or not present in cookies.");
        }
        String accessToken = extractTokenFromRequest(request);
        logger.debug("Access token extracted: {}", accessToken);
        return new String[] { refreshToken, accessToken };
    }

    private String extractTokenFromRequest(HttpServletRequest request) throws TokenNotFoundException {
        logger.debug("Extracting access token from Authorization header");
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            String token = bearerToken.substring(7); // Extract the token part after "Bearer "
            logger.debug("Access token found in Authorization header: {}", token);
            return token;
        }
        logger.warn("Authorization header with Bearer token is missing.");
        throw new TokenNotFoundException("Authorization header with Bearer token is missing.");
    }
}