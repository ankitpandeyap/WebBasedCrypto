package com.robspecs.Cryptography.dto;

import java.time.LocalDateTime;

public class MessageSummaryDTO {
	private Long messageId;
	private String senderUsername;
	// --- REVERTED: Bring back encryptedContent for text messages ---
	private String encryptedContent; // This will hold base64 encoded encrypted content for TEXT messages
	// --- END REVERTED ---
	private String encryptionType;
	private LocalDateTime timestamp;
	private String receiverUsername;
    private boolean isRead;
    private boolean isStarred;

    // --- EXISTING FIELDS FOR FILES ---
    private boolean isFile;
    private String originalFileName;
    private String contentType;
    // --- END EXISTING FIELDS ---

    // --- MODIFIED CONSTRUCTOR: For TEXT messages ---
    public MessageSummaryDTO(Long messageId, String senderUsername, String encryptedContent, String encryptionType,
                             LocalDateTime timestamp, String receiverUsername, boolean isRead, boolean isStarred) {
        this.messageId = messageId;
        this.senderUsername = senderUsername;
        this.encryptedContent = encryptedContent; // Set encryptedContent for text
        this.encryptionType = encryptionType;
        this.timestamp = timestamp;
        this.receiverUsername = receiverUsername;
        this.isRead = isRead;
        this.isStarred = isStarred;
        this.isFile = false; // Always false for this constructor
        this.originalFileName = null;
        this.contentType = null;
    }

    // --- NEW CONSTRUCTOR: For FILE messages ---
    public MessageSummaryDTO(Long messageId, String senderUsername, String encryptionType,
                             LocalDateTime timestamp, String receiverUsername, boolean isRead, boolean isStarred,
                             boolean isFile, String originalFileName, String contentType) {
        this.messageId = messageId;
        this.senderUsername = senderUsername;
        this.encryptedContent = null; // Set encryptedContent to null for files
        this.encryptionType = encryptionType;
        this.timestamp = timestamp;
        this.receiverUsername = receiverUsername;
        this.isRead = isRead;
        this.isStarred = isStarred;
        this.isFile = isFile;
        this.originalFileName = originalFileName;
        this.contentType = contentType;
    }
    // --- END MODIFIED CONSTRUCTORS ---

    // --- Default constructor (if needed by frameworks like Spring) ---
    public MessageSummaryDTO() { }

    // --- Getters ---
    public Long getMessageId() {
        return messageId;
    }

    public String getSenderUsername() {
        return senderUsername;
    }

    // --- REVERTED GETTER ---
    public String getEncryptedContent() {
        return encryptedContent;
    }
    // --- END REVERTED GETTER ---

    public String getEncryptionType() {
        return encryptionType;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getReceiverUsername() {
        return receiverUsername;
    }

    public boolean isRead() {
        return isRead;
    }

    public boolean isStarred() {
        return isStarred;
    }

    public boolean isFile() {
        return isFile;
    }

    public String getOriginalFileName() {
        return originalFileName;
    }

    public String getContentType() {
        return contentType;
    }

    // --- Setters (if needed, but for DTOs often omitted for immutability after construction) ---
    public void setMessageId(Long messageId) {
        this.messageId = messageId;
    }

    public void setSenderUsername(String senderUsername) {
        this.senderUsername = senderUsername;
    }

    // --- REVERTED SETTER ---
    public void setEncryptedContent(String encryptedContent) {
        this.encryptedContent = encryptedContent;
    }
    // --- END REVERTED SETTER ---

    public void setEncryptionType(String encryptionType) {
        this.encryptionType = encryptionType;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public void setReceiverUsername(String receiverUsername) {
        this.receiverUsername = receiverUsername;
    }

    public void setRead(boolean read) {
        isRead = read;
    }

    public void setStarred(boolean starred) {
        isStarred = starred;
    }

    public void setFile(boolean file) {
        isFile = file;
    }

    public void setOriginalFileName(String originalFileName) {
        this.originalFileName = originalFileName;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }
}