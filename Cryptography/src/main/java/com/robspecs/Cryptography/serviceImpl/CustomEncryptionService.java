package com.robspecs.Cryptography.serviceImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.EncryptionService;

@Service("CUSTOM")
public class CustomEncryptionService implements EncryptionService {

    private static final int SHIFT = 3;
    private static final Logger logger = LoggerFactory.getLogger(CustomEncryptionService.class);

    @Override
    public String encrypt(String rawMessage, String passkey) {
        logger.debug("Encrypting message using CUSTOM encryption");
        StringBuilder encrypted = new StringBuilder();
        for (char c : rawMessage.toCharArray()) {
            encrypted.append((char)(c + SHIFT));
        }
        String encryptedMessage = encrypted.reverse().toString();
        logger.debug("Message encrypted successfully");
        return encryptedMessage;
    }

    @Override
    public String decrypt(String encryptedMessage, String passkey) {
        logger.debug("Decrypting message using CUSTOM encryption");
        StringBuilder reversed = new StringBuilder(encryptedMessage).reverse();
        StringBuilder decrypted = new StringBuilder();
        for (char c : reversed.toString().toCharArray()) {
            decrypted.append((char)(c - SHIFT));
        }
        String decryptedMessage = decrypted.toString();
        logger.debug("Message decrypted successfully");
        return decryptedMessage;
    }
}
