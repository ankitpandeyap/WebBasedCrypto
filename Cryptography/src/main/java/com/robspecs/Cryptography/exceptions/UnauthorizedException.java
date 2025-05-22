 	package com.robspecs.Cryptography.exceptions;

 	import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

 	/**
 	 * Custom exception for unauthorized access (HTTP 401).
 	 * This will automatically map to a 401 status if thrown from a controller.
 	 * Note: For authentication failures, Spring Security's AuthenticationEntryPoint is usually used.
 	 * This is more for business logic unauthorized access.
 	 */
 	@ResponseStatus(HttpStatus.FORBIDDEN) // Changed from UNAUTHORIZED (401) to FORBIDDEN (403)
 	public class UnauthorizedException extends RuntimeException {
 	    public UnauthorizedException(String message) {
 	        super(message);
 	    }

 	    public UnauthorizedException(String message, Throwable cause) {
 	        super(message, cause);
 	    }
 	}