package com.robspecs.Cryptography.dto;

import java.time.LocalDateTime;

public class MessageSummaryDTO {
	private Long messageId;
	private String senderEmail;
	private String encryptedContent;
	private String encryptionType;
	private LocalDateTime timestamp;

	public MessageSummaryDTO(Long messageId, String senderEmail, String encryptedContent, String encryptionType,
			LocalDateTime timestamp) {
		this.messageId = messageId;
		this.senderEmail = senderEmail;
		this.encryptedContent = encryptedContent;
		this.encryptionType = encryptionType;
		this.timestamp = timestamp;
	}

	public Long getMessageId() {
		return messageId;
	}

	public String getSenderEmail() {
		return senderEmail;
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
}