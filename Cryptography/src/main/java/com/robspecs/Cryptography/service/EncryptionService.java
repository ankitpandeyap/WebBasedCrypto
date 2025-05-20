package com.robspecs.Cryptography.service;

public interface EncryptionService {
	String encrypt(String rawMessage, String passkey) throws Exception;
    String decrypt(String encryptedMessage, String passkey) throws Exception;
}
