package com.robspecs.Cryptography.Entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "decryption_keys")
public class DecryptionKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "message_id", nullable = false, unique = true)
    private Message message;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedKey;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Message getMessage() {
		return message;
	}

	public void setMessage(Message message) {
		this.message = message;
	}

	public String getEncryptedKey() {
		return encryptedKey;
	}

	public void setEncryptedKey(String encryptedKey) {
		this.encryptedKey = encryptedKey;
	}  // The key encrypted using the receiver's passkey
}
