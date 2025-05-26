package com.robspecs.Cryptography.serviceImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.EncryptionService;

@Service("CUSTOM")
public class CustomEncryptionService implements EncryptionService {

    // private static final int SHIFT = 3; // No longer static
    private static final Logger logger = LoggerFactory.getLogger(CustomEncryptionService.class);

    // Method to derive shift from passkey
    private int getShift(String passkey) {
        if (passkey == null || passkey.isEmpty()) {
            return 3; // Default shift if no passkey (or throw error)
        }
        // A simple way to derive shift from passkey: sum of char values modulo a max shift
        int shift = 0;
        for (char c : passkey.toCharArray()) {
            shift += (int) c;
        }
        return (shift % 26) + 1; // Shift between 1 and 26
    }

    @Override
    public String encrypt(String rawMessage, String passkey) {
        int shift = getShift(passkey);
        logger.debug("Encrypting message using CUSTOM encryption with shift: {}", shift);
        StringBuilder encrypted = new StringBuilder();
        for (char c : rawMessage.toCharArray()) {
            encrypted.append((char)(c + shift));
        }
        String encryptedMessage = encrypted.reverse().toString();
        logger.debug("Message encrypted successfully");
        return encryptedMessage;
    }

    @Override
    public String decrypt(String encryptedMessage, String passkey) {
        int shift = getShift(passkey);
        logger.debug("Decrypting message using CUSTOM encryption with shift: {}", shift);
        StringBuilder reversed = new StringBuilder(encryptedMessage).reverse();
        StringBuilder decrypted = new StringBuilder();
        for (char c : reversed.toString().toCharArray()) {
            decrypted.append((char)(c - shift));
        }
        String decryptedMessage = decrypted.toString();
        logger.debug("Message decrypted successfully");
        return decryptedMessage;
    }
}