package com.robspecs.Cryptography.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom exception for general encryption/decryption failures (e.g., malformed data, crypto errors).
 * Maps to HTTP 500 Internal Server Error.
 */
@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class EncryptionDecryptionException extends RuntimeException {
    /**
	 *
	 */
	private static final long serialVersionUID = 1L;

	public EncryptionDecryptionException(String message) {
        super(message);
    }

    public EncryptionDecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
