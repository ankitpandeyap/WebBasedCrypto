package com.robspecs.Cryptography.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom exception for when an OTP request is made too soon after a previous one.
 * Maps to HTTP 429 Too Many Requests.
 */
@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS) // HTTP 429
public class OtpCooldownException extends RuntimeException {
    public OtpCooldownException(String message) {
        super(message);
    }

    public OtpCooldownException(String message, Throwable cause) {
        super(message, cause);
    }
}