package com.robspecs.Cryptography.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR) // Or HttpStatus.BAD_REQUEST if user's fault
public class MissingEncryptionKeyException extends RuntimeException {
    /**
	 *
	 */
	private static final long serialVersionUID = 1L;

	public MissingEncryptionKeyException(String message) {
        super(message);
    }

    public MissingEncryptionKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}