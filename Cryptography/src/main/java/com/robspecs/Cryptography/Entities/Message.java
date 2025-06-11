package com.robspecs.Cryptography.Entities;

import java.time.LocalDateTime;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob; // <--- ADD THIS IMPORT
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "messages")
public class Message {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long messageId;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "sender_id", nullable = false)
	private User sender;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "receiver_id", nullable = false)
	private User receiver;

	@Lob // <--- ADD THIS ANNOTATION
	@Column(nullable = false, columnDefinition = "LONGBLOB")
	// This column will now store raw encrypted content (could be text or file bytes)
	private byte[] encryptedContent; // <--- CHANGE TYPE FROM String TO byte[]

	@OneToOne(mappedBy = "message", cascade = CascadeType.ALL, orphanRemoval = true)
	private DecryptionKey decryptionKey;

	@Column(nullable = false)
	private String encryptionType; // e.g. AES, RSA, CUSTOM

	// <--- ADD THIS NEW FIELD FOR MESSAGE TYPE
	@Column(nullable = false)
	private String messageType; // e.g., "TEXT", "FILE"
	// --- END NEW FIELD ---

	@Column(nullable = false)
	private LocalDateTime timestamp = LocalDateTime.now();

	@Column(nullable = false)
	private boolean isRead = false;

	@Column(nullable = false)
	private boolean isStarred = false;

    // --- NEW FIELDS FOR FILES (FOR STEP 3) ---
    @Column(length = 255) // Stores the original name of the uploaded file
    private String originalFileName;

    @Column(length = 100) // Stores the MIME type of the file (e.g., "image/jpeg", "application/pdf")
    private String contentType;

    private Long fileSize; // Stores the size of the original file in bytes
    // --- END NEW FIELDS ---

	// --- Existing Getters and Setters (KEEP THESE AS IS) ---
	public Long getMessageId() {
		return messageId;
	}

	public void setMessageId(Long messageId) {
		this.messageId = messageId;
	}

	public User getSender() {
		return sender;
	}

	public void setSender(User sender) {
		this.sender = sender;
	}

	public User getReceiver() {
		return receiver;
	}

	public void setReceiver(User receiver) {
		this.receiver = receiver;
	}

	// <--- UPDATE GETTER/SETTER RETURN/PARAMETER TYPE
	public byte[] getEncryptedContent() {
		return encryptedContent;
	}

	public void setEncryptedContent(byte[] encryptedContent) {
		this.encryptedContent = encryptedContent;
	}
	// --- END UPDATE ---

	public DecryptionKey getDecryptionKey() {
		return decryptionKey;
	}

	public void setDecryptionKey(DecryptionKey decryptionKey) {
		this.decryptionKey = decryptionKey;
	}

	public String getEncryptionType() {
		return encryptionType;
	}

	public void setEncryptionType(String encryptionType) {
		this.encryptionType = encryptionType;
	}

	// <--- ADD NEW GETTER/SETTER FOR messageType
	public String getMessageType() {
		return messageType;
	}

	public void setMessageType(String messageType) {
		this.messageType = messageType;
	}
	// --- END NEW GETTER/SETTER ---

	public LocalDateTime getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(LocalDateTime timestamp) {
		this.timestamp = timestamp;
	}

	public boolean isRead() {
		return isRead;
	}

	public void setRead(boolean isRead) {
		this.isRead = isRead;
	}

	public boolean isStarred() {
		return isStarred;
	}

	public void setStarred(boolean isStarred) {
		this.isStarred = isStarred;
	}
    // --- End Existing Getters and Setters ---


    // --- NEW GETTERS AND SETTERS FOR FILES (FOR STEP 3) ---
    public String getOriginalFileName() {
        return originalFileName;
    }

    public void setOriginalFileName(String originalFileName) {
        this.originalFileName = originalFileName;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public Long getFileSize() {
        return fileSize;
    }

    public void setFileSize(Long fileSize) {
        this.fileSize = fileSize;
    }
    // --- END NEW GETTERS AND SETTERS ---
}