package com.robspecs.Cryptography.dto;

import com.robspecs.Cryptography.Enums.Algorithm;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class MessageRequestDTO {

	 @NotBlank(message = "Receiver username is required")
	    private String toUsername;

	    @NotBlank(message = "Message content is required")
	    private String rawMessage;

	    @NotNull(message = "Encryption algorithm is required")
	    private Algorithm algorithm;

	    // Getters & Setters
	    public String getToUsername() { return toUsername; }
	    public void setToUsername(String toUsername) { this.toUsername = toUsername; }

	    public String getRawMessage() { return rawMessage; }
	    public void setRawMessage(String rawMessage) { this.rawMessage = rawMessage; }

	    public Algorithm getAlgorithm() { return algorithm; }
	    public void setAlgorithm(Algorithm algorithm) { this.algorithm = algorithm; }
	
}
