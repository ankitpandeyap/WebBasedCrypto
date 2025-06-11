package com.robspecs.Cryptography.service;

public interface EncryptionService {
	String encrypt(String rawMessage, String passkey) throws Exception;
    String decrypt(String encryptedMessage, String passkey) throws Exception;
    
    byte[] encrypt(byte[] rawBytes, String keyString) throws Exception;
    byte[] decrypt(byte[] encryptedBytesWithIv, String keyString) throws Exception;
}
