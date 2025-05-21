package com.robspecs.Cryptography.security;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.robspecs.Cryptography.dto.LoginDTO;
import com.robspecs.Cryptography.utils.JWTUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {

	private final AuthenticationManager authenticationManager;
	private final JWTUtils jwtUtil;
    private final static Logger logger = LoggerFactory.getLogger(JWTAuthenticationFilter.class);

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTUtils jwtUtil) {
		this.authenticationManager = authenticationManager;
		this.jwtUtil = jwtUtil;
        logger.info("JWTAuthenticationFilter initialized."); // Log filter initialization
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		logger.debug("Entering JWTAuthenticationFilter for request URI: {}", request.getRequestURI()); // Log method entry

		if (!request.getServletPath().equals("/api/auth/login")) {
			logger.debug("Request path {} is not /api/auth/login. Skipping authentication filter.", request.getServletPath());
			filterChain.doFilter(request, response);
			return;
		}

		logger.info("Processing login request for path: {}", request.getServletPath()); // Info for actual login attempt

		try {
			ObjectMapper objectMapper = new ObjectMapper();
			LoginDTO loginRequest = objectMapper.readValue(request.getInputStream(), LoginDTO.class);
            logger.debug("Login request payload parsed for user: {}", loginRequest.getUsernameOrEmail()); // Log parsed payload

			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
					loginRequest.getUsernameOrEmail(), loginRequest.getPassword());
            logger.debug("Created UsernamePasswordAuthenticationToken for user: {}", loginRequest.getUsernameOrEmail()); // Log token creation

			Authentication authResult = authenticationManager.authenticate(authToken);
            logger.debug("AuthenticationManager returned result for user: {}", authResult.getName()); // Log authentication result

			UserDetails userDetails = (UserDetails) authResult.getPrincipal();
            logger.debug("User details principal obtained: {}", userDetails.getUsername()); // Log principal details

			if(!userDetails.isEnabled()) {
				logger.warn("Authentication failed for user {} - profile not enabled. Throwing exception.", userDetails.getUsername()); // Warn if not enabled
				throw new Exception("Profile not verified Re-Verfiy Profile");
			}
            logger.debug("User {} profile is enabled. Proceeding with token generation.", userDetails.getUsername()); // Debug if enabled


			if (authResult.isAuthenticated()) {
                logger.info("User: {} authenticated successfully. Generating tokens.", userDetails.getUsername()); // Info for successful authentication
				String token = jwtUtil.generateToken(loginRequest.getUsernameOrEmail(), 15); // 15min
				response.setHeader("Authorization", "Bearer " + token);
                logger.debug("Access Token generated and set in Authorization header (first 10 chars): {}", token.substring(0, Math.min(token.length(), 10)) + "..."); // Debug partial token

				String refreshToken = jwtUtil.generateToken(loginRequest.getUsernameOrEmail(), 7 * 24 * 60);
				Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
				refreshCookie.setHttpOnly(true);
				refreshCookie.setSecure(false); // Set to true in production with HTTPS
				refreshCookie.setPath("/api/auth/refresh"); // Required for cookie to be sent to all endpoints
				refreshCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days in seconds
				response.addCookie(refreshCookie);
                logger.debug("Refresh Token generated and set as HTTP-Only cookie (first 10 chars): {}", refreshToken.substring(0, Math.min(refreshToken.length(), 10)) + "..."); // Debug partial refresh token

				response.setContentType("application/json");
				response.getWriter().write("{\"message\":\"Login successful\"}");
                logger.info("Login successful response sent for user: {}.", userDetails.getUsername()); // Info for response sent

			} else {
                logger.warn("Authentication result indicated not authenticated for user: {}", userDetails.getUsername()); // Warn if not authenticated
            }

		} catch (BadCredentialsException e) {
            logger.error("Authentication failed for user (Bad Credentials): {}", e.getMessage()); // Error for bad credentials
			request.setAttribute("custom-error", e.getMessage());
			request.setAttribute("custom-exception", e.getClass().getName());
			throw new BadCredentialsException("INTERNAL ERROR"); // Re-throwing original exception as per existing logic
		} catch (Exception e) {
            logger.error("Authentication failed due to unexpected error for request URI {}: {}", request.getRequestURI(), e.getMessage(), e); // Error for general exceptions with stack trace
			request.setAttribute("custom-error", e.getMessage());
			request.setAttribute("custom-exception", e.getClass().getName());
			throw new BadCredentialsException("INTERNAL ERROR"); // Re-throwing original exception as per existing logic
		}
        logger.debug("Exiting JWTAuthenticationFilter for request URI: {}", request.getRequestURI()); // Log method exit
	}
}