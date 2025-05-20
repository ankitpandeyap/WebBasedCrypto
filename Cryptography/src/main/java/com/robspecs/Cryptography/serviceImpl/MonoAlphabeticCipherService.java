package com.robspecs.Cryptography.serviceImpl;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.EncryptionService;

@Service("MONO_ALPHABETIC_CIPHER")
public class MonoAlphabeticCipherService implements EncryptionService {

    private static final Map<Character, Character> ENCRYPT_MAP = new HashMap<>();
    private static final Map<Character, Character> DECRYPT_MAP = new HashMap<>();
    private static final Logger logger = LoggerFactory.getLogger(MonoAlphabeticCipherService.class);

    static {
        String plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String cipher = "QWERTYUIOPASDFGHJKLZXCVBNM";
        logger.debug("Initializing MonoAlphabeticCipherService static maps");

        for (int i = 0; i < plain.length(); i++) {
            ENCRYPT_MAP.put(plain.charAt(i), cipher.charAt(i));
            DECRYPT_MAP.put(cipher.charAt(i), plain.charAt(i));
        }
        logger.debug("Encryption and decryption maps initialized");
    }

    @Override
    public String encrypt(String rawMessage, String passkey) {
        logger.debug("Encrypting message using MonoAlphabetic Cipher");
        StringBuilder encrypted = new StringBuilder();
        String upperCaseMessage = rawMessage.toUpperCase(); // Store the uppercase version
        for (char ch : upperCaseMessage.toCharArray()) {
            if (ENCRYPT_MAP.containsKey(ch)) {
                encrypted.append(ENCRYPT_MAP.get(ch));
            } else {
                encrypted.append(ch); // Keep punctuation, numbers unchanged
            }
        }
        String encryptedMessage = encrypted.toString();
        logger.debug("Message encrypted successfully");
        return encryptedMessage;
    }

    @Override
    public String decrypt(String encryptedMessage, String passkey) {
        logger.debug("Decrypting message using MonoAlphabetic Cipher");
        StringBuilder decrypted = new StringBuilder();
        String upperCaseMessage = encryptedMessage.toUpperCase(); // Store the uppercase version
        for (char ch : upperCaseMessage.toCharArray()) {
            if (DECRYPT_MAP.containsKey(ch)) {
                decrypted.append(DECRYPT_MAP.get(ch));
            } else {
                decrypted.append(ch);
            }
        }
        String decryptedMessage = decrypted.toString();
        logger.debug("Message decrypted successfully");
        return decryptedMessage;
    }
}
