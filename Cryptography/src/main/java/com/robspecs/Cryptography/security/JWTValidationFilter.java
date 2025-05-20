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
	}

	private static final List<String> PUBLIC_URLS = List.of("/api/auth/login", "/api/auth/refresh", "/api/auth/signup",
			"/api/auth/register", "/api/auth/otp/verify", "/api/auth/otp/request");

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String path = request.getRequestURI();

		if (PUBLIC_URLS.contains(path)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			String token = extractTokenFromRequest(request);
            logger.debug("Extracted token: {}", token);
			if (tokenService.isBlacklisted(token)) {
                logger.warn("Token is blacklisted: {}", token);
				// scope for improvement
				throw new JWTBlackListedTokenException("Acess token is Blacklisted");
			}
			String usernameFromToken = jwtUtil.validateAndExtractUsername(token);
            logger.debug("Username from token: {}", usernameFromToken);
			UserDetails currentUser = customUserDetailsService.loadUserByUsername(usernameFromToken);
			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(currentUser, null,
					currentUser.getAuthorities());
			authToken.setDetails(currentUser);
			authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			SecurityContextHolder.getContext().setAuthentication(authToken);
            logger.info("User: {} authenticated via JWT.", usernameFromToken);

		} catch (TokenNotFoundException e) {
            logger.error("Token not found: {}", e.getMessage());
			request.setAttribute("custom-error", "Token not found: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTTokenNotFoundException");
			throw new BadCredentialsException("Token not found");

		} catch (MissingClaimException e) {
            logger.error("Missing claim in token: {}", e.getMessage());
			request.setAttribute("custom-error", "Missing claim in token: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTTokenMissingClaimException");
			throw new BadCredentialsException("Missing claim in token");

		} catch (InvalidClaimException e) {
            logger.error("Invalid claim in token: {}", e.getMessage());
			request.setAttribute("custom-error", "Invalid claim in token: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTTokenInvalidClaimException");
			throw new BadCredentialsException("Invalid claim");

		} catch (UsernameNotFoundException e) {
            logger.error("Username not found: {}", e.getMessage());
			request.setAttribute("custom-error", "Username not found: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTTokenUsernameNotFoundException");
			throw new BadCredentialsException("Username not found");

		} catch (ExpiredJwtException e) {
            logger.warn("Token expired for user: {}", e.getClaims().getSubject());
			request.setAttribute("expiredToken", true);
			request.setAttribute("expiredTokenUsername", e.getClaims().getSubject());

		} catch (JwtException e) {
            logger.error("JWT parsing error: {}", e.getMessage());
			request.setAttribute("custom-error", "JWT parsing error: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTGeneralParsingException");
			throw new BadCredentialsException("Invalid JWT token");

		} catch (Exception e) {
            logger.error("Unhandled authentication error: {}", e.getMessage());
			request.setAttribute("custom-error", "Unhandled authentication error: " + e.getMessage());
			request.setAttribute("custom-exception", "UnexpectedAuthenticationException");
			throw new BadCredentialsException("Unexpected error");
		}
		filterChain.doFilter(request, response);
	}

	private String extractTokenFromRequest(HttpServletRequest request) throws TokenNotFoundException {
		String bearerToken = request.getHeader("Authorization");
		if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            String token = bearerToken.substring(7);
            logger.debug("Token extracted from Authorization header: {}", token);
			return token;
		}
        logger.warn("Authorization header does not contain a Bearer token.");
		throw new TokenNotFoundException(request.getLocalName() + " request doesn't contain token");
	}

}