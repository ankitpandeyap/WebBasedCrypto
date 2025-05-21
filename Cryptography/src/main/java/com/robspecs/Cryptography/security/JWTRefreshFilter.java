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
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.robspecs.Cryptography.exceptions.JWTBlackListedTokenException;
import com.robspecs.Cryptography.service.TokenBlacklistService;
import com.robspecs.Cryptography.utils.JWTUtils;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// Note: Using javax.security.sasl.AuthenticationException, consider using Spring Security's org.springframework.security.core.AuthenticationException
import javax.security.sasl.AuthenticationException;


@Component
public class JWTRefreshFilter extends OncePerRequestFilter {

	private final AuthenticationManager authenticationManager;
	private final JWTUtils jwtUtil;
	private final CustomUserDetailsService customUserDetailsService;
	private final TokenBlacklistService tokenService;
    private final static Logger logger = LoggerFactory.getLogger(JWTRefreshFilter.class);

	public JWTRefreshFilter(AuthenticationManager authenticationManager, JWTUtils jwtUtil,
			CustomUserDetailsService customUserDetailsService, TokenBlacklistService tokenService) {
		this.authenticationManager = authenticationManager;
		this.jwtUtil = jwtUtil;
		this.customUserDetailsService = customUserDetailsService;
		this.tokenService = tokenService;
        logger.info("JWTRefreshFilter initialized."); // Log filter initialization
	}

	private static final List<String> PUBLIC_URLS = List.of("/api/auth/login", "/api/auth/signup",
			"/api/auth/register", "/api/auth/otp/verify", "/api/auth/otp/request");

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		logger.debug("Entering JWTRefreshFilter for request URI: {}", request.getRequestURI()); // Log method entry

		String path = request.getRequestURI();
		Boolean isExpiredToken = (Boolean) request.getAttribute("expiredToken"); // null can be evaluated to false
		boolean isRefreshRequest = path.equals("/api/auth/refresh");
		boolean isAuthenticatedInContext = SecurityContextHolder.getContext().getAuthentication() != null &&
                                          SecurityContextHolder.getContext().getAuthentication().isAuthenticated();

		logger.debug("Current request state: Path='{}', IsRefreshRequest={}, IsExpiredToken={}, IsAuthenticatedInContext={}",
                     path, isRefreshRequest, isExpiredToken, isAuthenticatedInContext); // Log current request state


		if (PUBLIC_URLS.contains(path) && !isRefreshRequest) {
			logger.debug("Request path {} is public and not a refresh request. Skipping refresh filter.", path); // Log public path skip
			filterChain.doFilter(request, response);
			return;
		}

		// If token is NOT expired AND user is authenticated OR it's NOT a refresh call
		if (((isExpiredToken == null || !isExpiredToken) && isAuthenticatedInContext) || !isRefreshRequest) { // Corrected logic to match previous intent
            logger.debug("Conditions met to skip refresh logic. isExpiredToken={}, isAuthenticatedInContext={}, isRefreshRequest={}",
                         isExpiredToken, isAuthenticatedInContext, isRefreshRequest); // Log condition evaluation
			filterChain.doFilter(request, response);
			return;
		}

        logger.info("Proceeding with refresh token logic for path: {}", path); // Info for proceeding with refresh

		try {
			String usernameFromAccessToken = (String) request.getAttribute("expiredTokenUsername");
            logger.debug("Username from expired access token attribute: {}", usernameFromAccessToken); // Log username from expired token

			String refreshToken = extractJwtFromRequest(request);
			if (refreshToken == null) {
                logger.warn("Refresh token is null or not present in cookies for refresh request. Sending UNAUTHORIZED."); // Warn for missing refresh token
				throw new AuthenticationException("Refresh Token is Invalid or not present"); // As per existing logic
			}
            logger.debug("Refresh token extracted from cookie (first 10 chars): {}", refreshToken.substring(0, Math.min(refreshToken.length(), 10)) + "..."); // Debug partial refresh token

			if (tokenService.isBlacklisted(refreshToken)) {
                logger.warn("Refresh token is blacklisted: (first 10 chars) {}. Sending UNAUTHORIZED.", refreshToken.substring(0, Math.min(refreshToken.length(), 10)) + "..."); // Warn if blacklisted
				throw new JWTBlackListedTokenException("Acess token is Blacklisted"); // As per existing logic
			}
            logger.debug("Refresh token is not blacklisted."); // Debug if not blacklisted

			String usernameFromRefreshToken = jwtUtil.validateAndExtractUsername(refreshToken);
            logger.debug("Username extracted from refresh token: {}", usernameFromRefreshToken); // Log username from refresh token

			if (usernameFromAccessToken != null && !usernameFromAccessToken.equals(usernameFromRefreshToken)) {
                logger.warn("Username from access token ({}) does not match username from refresh token ({}). Sending UNAUTHORIZED.", usernameFromAccessToken, usernameFromRefreshToken); // Warn for username mismatch
				throw new AuthenticationException("Refresh Token is Invalid or not present"); // As per existing logic
			}
            logger.debug("Username from access token matches refresh token or is not applicable."); // Debug if usernames match

            // Load user details using the username from the refresh token
			UserDetails userDetails = customUserDetailsService.loadUserByUsername(usernameFromRefreshToken);
            logger.debug("User details loaded for refresh: {}", userDetails.getUsername()); // Log loaded user details

            // Create a new authentication token for the refreshed session
			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null,
					userDetails.getAuthorities());
            logger.debug("New authentication token created for user: {}", userDetails.getUsername()); // Log token creation

            // Generate a new access token
			String newAccessToken = jwtUtil.generateToken(userDetails.getUsername(), 15); // 15 min expiration for access token
            logger.info("New Access Token generated for user: {}.", userDetails.getUsername()); // Info for new access token

            // Set the new access token in the Authorization header
			response.setHeader("Authorization", "Bearer " + newAccessToken);
            logger.info("New Access Token set in Authorization header for user: {}.", userDetails.getUsername()); // Info for header set

            // Update the SecurityContextHolder with the new authentication
			SecurityContextHolder.getContext().setAuthentication(authToken);
            logger.info("Security Context updated with new authentication for user: {}.", userDetails.getUsername()); // Info for context update

			filterChain.doFilter(request, response); // Continue the filter chain
            logger.debug("Exiting JWTRefreshFilter after successful token refresh for user: {}", userDetails.getUsername()); // Log successful refresh exit

		} catch (ExpiredJwtException e) {
            logger.warn("Refresh token expired for user: {}. Message: {}", e.getClaims().getSubject(), e.getMessage()); // Warn for expired refresh token
            request.setAttribute("custom-error", "Refresh Token Expired. Please log in again."); // Set attribute for error handling
            request.setAttribute("custom-exception", e.getClass().getName()); // Set attribute for exception type
            throw new BadCredentialsException("Refresh token failure"); // Re-throwing original exception as per existing logic
        } catch (JWTBlackListedTokenException e) {
            logger.warn("Refresh token processing failed: Blacklisted token. Message: {}", e.getMessage()); // Warn for blacklisted refresh token
            request.setAttribute("custom-error", "Refresh Token Blacklisted. Please log in again."); // Set attribute for error handling
            request.setAttribute("custom-exception", e.getClass().getName()); // Set attribute for exception type
            throw new BadCredentialsException("Refresh token failure"); // Re-throwing original exception as per existing logic
        } catch (UsernameNotFoundException e) {
            logger.warn("Refresh token processing failed: Username from refresh token not found. Message: {}", e.getMessage()); // Warn for username not found from refresh token
            request.setAttribute("custom-error", "Invalid Refresh Token. User not found."); // Set attribute for error handling
            request.setAttribute("custom-exception", e.getClass().getName()); // Set attribute for exception type
            throw new BadCredentialsException("Refresh token failure"); // Re-throwing original exception as per existing logic
        } catch (AuthenticationException e) { // Catching javax.security.sasl.AuthenticationException
            logger.warn("Refresh token processing failed: AuthenticationException. Message: {}", e.getMessage()); // Warn for general AuthenticationException
            request.setAttribute("custom-error", "Refresh Token Invalid or Expired: " + e.getMessage()); // Set attribute for error handling
            request.setAttribute("custom-exception", e.getClass().getName()); // Set attribute for exception type
            throw new BadCredentialsException("Refresh token failure"); // Re-throwing original exception as per existing logic
        } catch (Exception e) {
            logger.error("Refresh token processing failed due to unexpected error for request URI {}: {}", request.getRequestURI(), e.getMessage(), e); // Error for unexpected issues with stack trace
			request.setAttribute("custom-error", "Refresh token failure due to internal error."); // Set attribute for error handling
			request.setAttribute("custom-exception", e.getClass().getName()); // Set attribute for exception type
			throw new BadCredentialsException("Refresh token failure"); // Re-throwing original exception as per existing logic
		}
        logger.debug("Exiting JWTRefreshFilter for request URI: {}", request.getRequestURI()); // Fallback exit log
	}

	private String extractJwtFromRequest(HttpServletRequest request) {
        logger.debug("Attempting to extract refresh token from cookies."); // Debug cookie extraction start
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
            logger.debug("No cookies found in the request."); // Debug if no cookies
			return null;
		}
		String refreshToken = null;
		for (Cookie cookie : cookies) {
			if ("refreshToken".equals(cookie.getName())) {
				refreshToken = cookie.getValue();
                logger.debug("Refresh token found in cookie: (first 10 chars) {}", refreshToken.substring(0, Math.min(refreshToken.length(), 10)) + "..."); // Debug partial refresh token
				break;
			}
		}
		if (refreshToken == null) {
            logger.debug("Refresh token cookie not found by name 'refreshToken'."); // Debug if specific cookie not found
        }
		return refreshToken;
	}
}