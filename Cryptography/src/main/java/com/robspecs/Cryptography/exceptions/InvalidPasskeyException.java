package com.robspecs.Cryptography.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom exception for an incorrect passkey provided during decryption.
 * Maps to HTTP 400 Bad Request or 403 Forbidden.
 */
@ResponseStatus(HttpStatus.FORBIDDEN) // Or HttpStatus.BAD_REQUEST
public class InvalidPasskeyException extends RuntimeException {
    /**
	 *
	 */
	private static final long serialVersionUID = 1L;

	public InvalidPasskeyException(String message) {
        super(message);
    }

    public InvalidPasskeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
