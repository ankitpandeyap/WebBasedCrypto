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
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		if (!request.getServletPath().equals("/api/auth/login")) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			ObjectMapper objectMapper = new ObjectMapper();
			LoginDTO loginRequest = objectMapper.readValue(request.getInputStream(), LoginDTO.class);
            logger.debug("Login request received for user: {}", loginRequest.getUsernameOrEmail());

			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
					loginRequest.getUsernameOrEmail(), loginRequest.getPassword());

			Authentication authResult = authenticationManager.authenticate(authToken);

			UserDetails userDetails = (UserDetails) authResult.getPrincipal();
			if(!userDetails.isEnabled()) {
				throw new Exception("Profile not verified Re-Verfiy Profile");
			}


			if (authResult.isAuthenticated()) {
                logger.info("User: {} authenticated successfully.", userDetails.getUsername());
				String token = jwtUtil.generateToken(authResult.getName(), 15); // 15min
				response.setHeader("Authorization", "Bearer " + token);
                logger.debug("Access Token generated: {}", token);

				String refreshToken = jwtUtil.generateToken(authResult.getName(), 7 * 24 * 60);
				Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
				refreshCookie.setHttpOnly(true);
				refreshCookie.setSecure(false);
				refreshCookie.setPath("/api/auth/refresh"); // Required for cookie to be sent to all endpoints
				refreshCookie.setMaxAge(7 * 24 * 60 * 60);
				response.addCookie(refreshCookie);
                logger.debug("Refresh Token generated and set as cookie.");
				response.setContentType("application/json");
				response.getWriter().write("{\"message\":\"Login successful\"}");
                logger.info("Login successful response sent.");


			}

		} catch (Exception e) {
            logger.error("Authentication failed: {}", e.getMessage());
			request.setAttribute("custom-error", e.getMessage());
			request.setAttribute("custom-exception", e.getClass().getName());
			throw new BadCredentialsException("INTERNAL ERROR");
		}
	}
}