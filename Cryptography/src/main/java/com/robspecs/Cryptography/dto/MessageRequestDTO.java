package com.robspecs.Cryptography.dto;

import com.robspecs.Cryptography.Enums.Algorithm;
import org.springframework.web.multipart.MultipartFile; // Import for MultipartFile

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
// You might need these for custom validation, but we'll manage in service for simplicity
// import jakarta.validation.constraints.AssertTrue; 

public class MessageRequestDTO {

	@NotBlank(message = "Receiver username is required")
	private String toUsername;

	// --- MODIFIED FIELD FOR STEP 7 ---
	// rawMessage is now optional at the DTO level because it might be a file upload.
	// Validation will be handled in the service layer to ensure EITHER rawMessage OR file is present.
	private String rawMessage; 
	// --- END MODIFIED FIELD ---

	@NotNull(message = "Encryption algorithm is required")
	private Algorithm algorithm;

    // --- NEW FIELD FOR FILE UPLOAD (FOR STEP 7) ---
    private MultipartFile file; // Represents the uploaded file (optional for text messages)
    // --- END NEW FIELD ---

	// Getters & Setters
	public String getToUsername() {
		return toUsername;
	}

	public void setToUsername(String toUsername) {
		this.toUsername = toUsername;
	}

	public String getRawMessage() {
		return rawMessage;
	}

	// This setter should be capable of accepting null if a file is uploaded
	public void setRawMessage(String rawMessage) {
		this.rawMessage = rawMessage;
	}

	public Algorithm getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(Algorithm algorithm) {
		this.algorithm = algorithm;
	}

    // --- NEW GETTER AND SETTER FOR FILE (FOR STEP 7) ---
    public MultipartFile getFile() {
        return file;
    }

    public void setFile(MultipartFile file) {
        this.file = file;
    }
    // --- END NEW GETTER AND SETTER ---

    // --- IMPORTANT: CUSTOM VALIDATION LOGIC FOR SERVICE LAYER (READ ONLY) ---
    // At the DTO level, we are removing @NotBlank from rawMessage to allow for files.
    // However, your service layer MUST implement logic to ensure:
    // 1. Either `rawMessage` is provided AND not blank, OR `file` is provided AND not empty.
    // 2. It is NOT valid for BOTH `rawMessage` AND `file` to be provided.
    // 3. It is NOT valid for NEITHER `rawMessage` NOR `file` to be provided.
    // This mutual exclusivity and presence check will be done in the MessageService.
}