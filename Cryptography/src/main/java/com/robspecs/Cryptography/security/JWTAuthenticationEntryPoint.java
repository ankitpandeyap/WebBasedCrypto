package com.robspecs.Cryptography.security;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;



import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JWTAuthenticationEntryPoint implements AuthenticationEntryPoint {
     private final static Logger  logger = LoggerFactory.getLogger(JWTAuthenticationEntryPoint.class);
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
	        logger.error("ENTER THE AUTHENTICATION POINT BAD REQUEST", request.getLocalAddr() + " " + request.getPathInfo());
		   response.sendError(HttpServletResponse.SC_BAD_REQUEST, "BAD CREDENTIALS");

	}

}
