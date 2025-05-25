package com.robspecs.Cryptography.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR) // Default HTTP status if not caught specifically
public class InboxRetrievalException extends RuntimeException {

    public InboxRetrievalException(String message) {
        super(message);
    }

    public InboxRetrievalException(String message, Throwable cause) {
        super(message, cause);
    }
}
