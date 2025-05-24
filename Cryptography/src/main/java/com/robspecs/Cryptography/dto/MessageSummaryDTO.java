package com.robspecs.Cryptography.dto;

import java.time.LocalDateTime;

public class MessageSummaryDTO {
	private Long messageId;
	private String senderUsername;
	private String encryptedContent;
	private String encryptionType;
	private LocalDateTime timestamp;
	private String receiverUsername; // <-- ADD THIS NEW FIELD

	public MessageSummaryDTO(Long messageId, String senderUsername, String encryptedContent, String encryptionType,
			LocalDateTime timestamp, String receiverUsername) { // <-- ADD receiverUsername to constructor
		this.messageId = messageId;
		this.senderUsername = senderUsername;
		this.encryptedContent = encryptedContent;
		this.encryptionType = encryptionType;
		this.timestamp = timestamp;
		this.receiverUsername = receiverUsername; // <-- INITIALIZE NEW FIELD
	}

	 public MessageSummaryDTO() { }
	
	public Long getMessageId() {
		return messageId;
	}

	public String getSenderUsername() {
		return senderUsername;
	}

	public String getEncryptedContent() {
		return encryptedContent;
	}

	public String getEncryptionType() {
		return encryptionType;
	}

	public LocalDateTime getTimestamp() {
		return timestamp;
	}

	public String getReceiverUsername() { // <-- ADD NEW GETTER
		return receiverUsername;
	}

	public void setMessageId(Long messageId) {
		this.messageId = messageId;
	}

	public void setSenderUsername(String senderUsername) {
		this.senderUsername = senderUsername;
	}

	public void setEncryptedContent(String encryptedContent) {
		this.encryptedContent = encryptedContent;
	}

	public void setEncryptionType(String encryptionType) {
		this.encryptionType = encryptionType;
	}

	public void setTimestamp(LocalDateTime timestamp) {
		this.timestamp = timestamp;
	}

	public void setReceiverUsername(String receiverUsername) {
		this.receiverUsername = receiverUsername;
	}
	
	
	
}