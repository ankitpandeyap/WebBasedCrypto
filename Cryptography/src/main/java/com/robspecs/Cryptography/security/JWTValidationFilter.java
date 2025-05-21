package com.robspecs.Cryptography.security;

import java.io.IOException;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.robspecs.Cryptography.exceptions.JWTBlackListedTokenException;
import com.robspecs.Cryptography.exceptions.TokenNotFoundException;
import com.robspecs.Cryptography.service.TokenBlacklistService;
import com.robspecs.Cryptography.utils.JWTUtils;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.InvalidClaimException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MissingClaimException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JWTValidationFilter extends OncePerRequestFilter {

	private final AuthenticationManager authenticationManager;
	private final JWTUtils jwtUtil;
	private final CustomUserDetailsService customUserDetailsService;
	private final TokenBlacklistService tokenService;
    private final static Logger logger = LoggerFactory.getLogger(JWTValidationFilter.class);

	public JWTValidationFilter(AuthenticationManager authenticationManager, JWTUtils jwtUtil,
			CustomUserDetailsService customUserDetailsService, TokenBlacklistService tokenService) {
		this.authenticationManager = authenticationManager;
		this.jwtUtil = jwtUtil;
		this.customUserDetailsService = customUserDetailsService;
		this.tokenService = tokenService;
        logger.info("JWTValidationFilter initialized."); // Log filter initialization
	}

	private static final List<String> PUBLIC_URLS = List.of("/api/auth/login", "/api/auth/refresh", "/api/auth/signup",
			"/api/auth/register", "/api/auth/otp/verify", "/api/auth/otp/request");

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		logger.debug("Entering JWTValidationFilter for request URI: {}", request.getRequestURI()); // Log method entry

		String path = request.getRequestURI();

		if (PUBLIC_URLS.contains(path)) {
			logger.debug("Request path {} is public. Skipping JWT validation.", path); // Log public path
			filterChain.doFilter(request, response);
			return;
		}
        logger.debug("Request path {} is protected. Proceeding with JWT validation.", path); // Log protected path

		try {
			String token = extractTokenFromRequest(request);
            logger.debug("Extracted token (first 10 chars): {}", token != null ? token.substring(0, Math.min(token.length(), 10)) + "..." : "null"); // Log partial token for security
			
            if (tokenService.isBlacklisted(token)) {
                logger.warn("Token is blacklisted: (first 10 chars) {}. Throwing exception.", token != null ? token.substring(0, Math.min(token.length(), 10)) + "..." : "null"); // Warn if blacklisted
				throw new JWTBlackListedTokenException("Acess token is Blacklisted");
			}
            logger.debug("Token is not blacklisted. Proceeding with validation."); // Debug if not blacklisted

			String usernameFromToken = jwtUtil.validateAndExtractUsername(token);
            logger.debug("Username extracted from token: {}", usernameFromToken); // Log extracted username

			UserDetails currentUser = customUserDetailsService.loadUserByUsername(usernameFromToken);
            logger.debug("User details loaded for: {}", currentUser.getUsername()); // Log loaded user details

			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(currentUser, null,
					currentUser.getAuthorities());
			
			authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            logger.debug("Authentication token created and details set for user: {}", currentUser.getUsername()); // Log token creation

			SecurityContextHolder.getContext().setAuthentication(authToken);
            logger.info("User: {} authenticated via JWT and SecurityContextHolder updated.", usernameFromToken); // Info for successful authentication

		} catch (TokenNotFoundException e) {
            logger.warn("JWT validation failed: Token not found in request. Message: {}", e.getMessage()); // Warn for token not found
			request.setAttribute("custom-error", "Token not found: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTTokenNotFoundException");
			throw new BadCredentialsException("Token not found");
		} catch (MissingClaimException e) {
            logger.warn("JWT validation failed: Missing claim in token. Message: {}", e.getMessage()); // Warn for missing claim
			request.setAttribute("custom-error", "Missing claim in token: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTTokenMissingClaimException");
			throw new BadCredentialsException("Missing claim in token");
		} catch (InvalidClaimException e) {
            logger.warn("JWT validation failed: Invalid claim in token. Message: {}", e.getMessage()); // Warn for invalid claim
			request.setAttribute("custom-error", "Invalid claim in token: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTTokenInvalidClaimException");
			throw new BadCredentialsException("Invalid claim");
		} catch (UsernameNotFoundException e) {
            logger.warn("JWT validation failed: Username from token not found in DB. Message: {}", e.getMessage()); // Warn for username not found
			request.setAttribute("custom-error", "Username not found: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTTokenUsernameNotFoundException");
			throw new BadCredentialsException("Username not found");
		} catch (ExpiredJwtException e) {
            logger.warn("JWT validation failed: Token expired for user: {}. Setting attributes for refresh filter.", e.getClaims().getSubject()); // Warn for expired token
			request.setAttribute("expiredToken", true);
			request.setAttribute("expiredTokenUsername", e.getClaims().getSubject());
		} catch (JWTBlackListedTokenException e) {
            logger.warn("JWT validation failed: Blacklisted token. Message: {}", e.getMessage()); // Warn for blacklisted token
            request.setAttribute("custom-error", "Authentication failed: Blacklisted token.");
            request.setAttribute("custom-exception", "JWTBlackListedTokenException");
            throw new BadCredentialsException("Access token is Blacklisted"); // Re-throwing original exception as per existing logic
        } catch (JwtException e) {
            logger.error("JWT validation failed: General JWT parsing error. Message: {}", e.getMessage(), e); // Error for general JWT issues with stack trace
			request.setAttribute("custom-error", "JWT parsing error: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTGeneralParsingException");
			throw new BadCredentialsException("Invalid JWT token");
		} catch (Exception e) {
            logger.error("JWT validation failed: Unhandled authentication error for request URI {}. Message: {}", request.getRequestURI(), e.getMessage(), e); // Error for unexpected issues with stack trace
			request.setAttribute("custom-error", "Unhandled authentication error: " + e.getMessage());
			request.setAttribute("custom-exception", "UnexpectedAuthenticationException");
			throw new BadCredentialsException("Unexpected error");
		}
		filterChain.doFilter(request, response);
        logger.debug("Exiting JWTValidationFilter for request URI: {}", request.getRequestURI()); // Log method exit
	}

	private String extractTokenFromRequest(HttpServletRequest request) throws TokenNotFoundException {
        logger.debug("Attempting to extract token from Authorization header."); // Debug token extraction start
		String bearerToken = request.getHeader("Authorization");
		if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            String token = bearerToken.substring(7);
            logger.debug("Token successfully extracted from Authorization header (first 10 chars): {}", token.substring(0, Math.min(token.length(), 10)) + "..."); // Debug partial token
			return token;
		}
        logger.warn("Authorization header does not contain a Bearer token or is malformed."); // Warn if token not found
		throw new TokenNotFoundException("Authorization header missing or invalid Bearer token.");
	}

}