package com.robspecs.Cryptography.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom exception for when a user exceeds the maximum number of OTP verification attempts.
 * Maps to HTTP 429 Too Many Requests or 403 Forbidden.
 */
@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS) // HTTP 429
public class TooManyOtpAttemptsException extends RuntimeException {
    public TooManyOtpAttemptsException(String message) {
        super(message);
    }

    public TooManyOtpAttemptsException(String message, Throwable cause) {
        super(message, cause);
    }
}