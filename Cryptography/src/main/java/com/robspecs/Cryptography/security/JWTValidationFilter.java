package com.robspecs.Cryptography.security;

import java.io.IOException;
import java.util.List;

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
			if (tokenService.isBlacklisted(token)) {
				// scope for improvement
				throw new JWTBlackListedTokenException("Acess token is Blacklisted");
			}
			String usernameFromToken = jwtUtil.validateAndExtractUsername(token);
			UserDetails currentUser = customUserDetailsService.loadUserByUsername(usernameFromToken);
			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(currentUser, null,
					currentUser.getAuthorities());
			authToken.setDetails(currentUser);
			authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			SecurityContextHolder.getContext().setAuthentication(authToken);

		} catch (TokenNotFoundException e) {
			request.setAttribute("custom-error", "Token not found: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTTokenNotFoundException");
			throw new BadCredentialsException("Token not found");

		} catch (MissingClaimException e) {
			request.setAttribute("custom-error", "Missing claim in token: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTTokenMissingClaimException");
			throw new BadCredentialsException("Missing claim in token");

		} catch (InvalidClaimException e) {
			request.setAttribute("custom-error", "Invalid claim in token: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTTokenInvalidClaimException");
			throw new BadCredentialsException("Invalid claim");

		} catch (UsernameNotFoundException e) {
			request.setAttribute("custom-error", "Username not found: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTTokenUsernameNotFoundException");
			throw new BadCredentialsException("Username not found");

		} catch (ExpiredJwtException e) {
			request.setAttribute("expiredToken", true);
			request.setAttribute("expiredTokenUsername", e.getClaims().getSubject());

		} catch (JwtException e) {
			request.setAttribute("custom-error", "JWT parsing error: " + e.getMessage());
			request.setAttribute("custom-exception", "JWTGeneralParsingException");
			throw new BadCredentialsException("Invalid JWT token");

		} catch (Exception e) {
			request.setAttribute("custom-error", "Unhandled authentication error: " + e.getMessage());
			request.setAttribute("custom-exception", "UnexpectedAuthenticationException");
			throw new BadCredentialsException("Unexpected error");
		}
		filterChain.doFilter(request, response);
	}

	private String extractTokenFromRequest(HttpServletRequest request) throws TokenNotFoundException {
		String bearerToken = request.getHeader("Authorization");
		if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7);
		}
		throw new TokenNotFoundException(request.getLocalName() + " request doesn't contain token");
	}

}
