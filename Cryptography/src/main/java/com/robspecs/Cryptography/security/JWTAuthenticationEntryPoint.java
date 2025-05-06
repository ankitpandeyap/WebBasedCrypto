package com.robspecs.Cryptography.security;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JWTAuthenticationEntryPoint implements AuthenticationEntryPoint {
	private final static Logger logger = LoggerFactory.getLogger(JWTAuthenticationEntryPoint.class);

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		logger.error("ENTER THE AUTHENTICATION POINT BAD REQUEST",
				request.getLocalAddr() + " " + request.getPathInfo());

		String message = authException.getMessage();
		String customExceptionType = "AuthenticationException";

		Object customError = request.getAttribute("custom-error");
		if (customError != null) {
			message = customError.toString();
		}

		Object exceptionType = request.getAttribute("custom-exception");
		if (exceptionType != null) {
			customExceptionType = exceptionType.toString();
		}

		Map<String, Object> errorDetails = new HashMap<>();
		errorDetails.put("timestamp", LocalDateTime.now().toString());
		errorDetails.put("status", HttpServletResponse.SC_UNAUTHORIZED);
		errorDetails.put("error", "Unauthorized");
		errorDetails.put("message", message);
		errorDetails.put("path", request.getRequestURL().toString());
		errorDetails.put("exceptionType", customExceptionType);
		errorDetails.put("client", request.getRemoteAddr());
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType("application/json");

		ObjectMapper mapper = new ObjectMapper();
		mapper.writeValue(response.getOutputStream(), errorDetails);
	}

}
