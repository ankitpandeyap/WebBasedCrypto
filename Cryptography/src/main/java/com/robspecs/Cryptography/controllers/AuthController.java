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

    @Autowired
    public AuthController(AuthService authService, StringRedisTemplate redisTemplate,
            TokenBlacklistService tokenService) {
        this.authService = authService;
        this.redisTemplate = redisTemplate;
        this.tokenService = tokenService;
    }

    @PostMapping({ "/register", "/signup" })
    public ResponseEntity<?> signup(@RequestBody RegistrationDTO currDTO) {
        String verifiedFlagKey = currDTO.getEmail() + ":verified";
        String otpVerified = redisTemplate.opsForValue().get(verifiedFlagKey); // Check the new key

        // Check if the email has been successfully verified via OTP
        if (!"true".equals(otpVerified)) { // Expect "true" as the value
            return new ResponseEntity<>("Email has not been verified via OTP or verification expired. Please request and verify OTP again.", HttpStatus.BAD_REQUEST);
        }

        // If OTP is verified, proceed with user registration
        authService.registerNewUser(currDTO);

        // IMPORTANT: Clean up the verification flag after successful registration
        redisTemplate.delete(verifiedFlagKey);

        return ResponseEntity.ok("User registered successfully!");
    }

    // APIS FOR VALIDATING THE TOKEN
    @GetMapping("/validate")
    public String validateToken() {
        return "Token is valid ✅";
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws RuntimeException {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null) {
                String[] tokens = getRefreshAndAcessToken(request);
                // Blacklist refresh token (e.g., 5 minutes or until it expires)
                tokenService.blacklistToken(tokens[0], 300);
                // Blacklist access token (e.g., 30 seconds or until it expires)
                tokenService.blacklistToken(tokens[1], 30);
                SecurityContextHolder.clearContext();

                // Expire refresh token cookie in the browser
                Cookie expiredCookie = new Cookie("refreshToken", null);
                expiredCookie.setMaxAge(0); // Set max age to 0 to delete the cookie
                expiredCookie.setHttpOnly(true); // Should be HttpOnly for security
                expiredCookie.setPath("/"); // Ensure path matches the original cookie path
                response.addCookie(expiredCookie);
            }
            return ResponseEntity.ok("User logged out successfully.");
        } catch (RuntimeException e) {
            // Catch specific exceptions like JWTTokenNotFoundException for more tailored responses
            if (e instanceof JWTTokenNotFoundException || e instanceof TokenNotFoundException) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Logout failed: " + e.getMessage());
            }
            return ResponseEntity.internalServerError().body("Logout unsuccessful: " + e.getLocalizedMessage());
        }
    }

    String[] getRefreshAndAcessToken(HttpServletRequest request) throws JWTTokenNotFoundException {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            throw new JWTTokenNotFoundException("No cookies found in request.");
        }
        String refreshToken = null;
        for (Cookie cookie : cookies) {
            if ("refreshToken".equals(cookie.getName())) {
                refreshToken = cookie.getValue();
                break;
            }
        }
        if (refreshToken == null) {
            throw new JWTTokenNotFoundException("Refresh Token is missing or not present in cookies.");
        }
        String accessToken = extractTokenFromRequest(request);
        return new String[] { refreshToken, accessToken };
    }

    private String extractTokenFromRequest(HttpServletRequest request) throws TokenNotFoundException {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Extract the token part after "Bearer "
        }
        throw new TokenNotFoundException("Authorization header with Bearer token is missing.");
    }
}