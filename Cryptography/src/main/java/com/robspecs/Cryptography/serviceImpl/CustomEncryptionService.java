package com.robspecs.Cryptography.serviceImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.EncryptionService;
import java.nio.charset.StandardCharsets; // Added for String to byte[] conversion

@Service("CUSTOM")
public class CustomEncryptionService implements EncryptionService {

    private static final Logger logger = LoggerFactory.getLogger(CustomEncryptionService.class);

    // Method to derive shift from passkey
    private int getShift(String passkey) {
        if (passkey == null || passkey.isEmpty()) {
            return 3; // Default shift if no passkey (or throw error)
        }
        // A simple way to derive shift from passkey: sum of char values modulo a max shift
        int shift = 0;
        for (char c : passkey.toCharArray()) {
            shift += c;
        }
        return (shift % 26) + 1; // Shift between 1 and 26. Note: For byte-wise shift, using % 256 would be more general.
    }

    // --- EXISTING STRING METHODS (MODIFIED TO DELEGATE) ---
    @Override
    public String encrypt(String rawMessage, String passkey) throws Exception { // Added throws Exception for interface compatibility
        logger.debug("Encrypting text message using CUSTOM encryption.");
        // Convert string to bytes
        byte[] rawBytes = rawMessage.getBytes(StandardCharsets.UTF_8);
        // Encrypt bytes using the new byte[] method
        byte[] encryptedBytes = encrypt(rawBytes, passkey); // Calls the new byte[] method
        // Convert encrypted bytes back to string for storage (Base64 is common for binary to string)
        return java.util.Base64.getEncoder().encodeToString(encryptedBytes); // Base64 encode for string storage
    }

    @Override
    public String decrypt(String encryptedMessage, String passkey) throws Exception { // Added throws Exception for interface compatibility
        logger.debug("Decrypting text message using CUSTOM encryption.");
        // Decode Base64 string to bytes
        byte[] encryptedBytes = java.util.Base64.getDecoder().decode(encryptedMessage);
        // Decrypt bytes using the new byte[] method
        byte[] decryptedBytes = decrypt(encryptedBytes, passkey); // Calls the new byte[] method
        // Convert decrypted bytes back to string
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
    // --- END MODIFIED EXISTING STRING METHODS ---


    // --- NEW METHODS FOR BINARY DATA (FILES) ---
    @Override
    public byte[] encrypt(byte[] rawBytes, String keyString) throws Exception {
        int shift = getShift(keyString);
        logger.debug("Encrypting {} bytes of binary data using CUSTOM encryption with shift: {}", rawBytes.length, shift);
        byte[] encrypted = new byte[rawBytes.length];
        for (int i = 0; i < rawBytes.length; i++) {
            // Apply shift to each byte. Use a simple modular arithmetic to keep it within byte range (0-255).
            // (byte + shift) % 256. Handle negative bytes by adding 256 if negative.
            encrypted[i] = (byte) ((rawBytes[i] + shift) % 256); // This is a very simplistic approach
        }
        // Note: For custom/mono ciphers, no IV is typically used unless you implement a more complex mode.
        // Returning just the encrypted bytes.
        logger.debug("Binary data encryption complete. Encrypted size: {} bytes.", encrypted.length);
        return encrypted;
    }

    @Override
    public byte[] decrypt(byte[] encryptedBytes, String keyString) throws Exception {
        int shift = getShift(keyString);
        logger.debug("Decrypting {} bytes of binary data using CUSTOM encryption with shift: {}", encryptedBytes.length, shift);
        byte[] decrypted = new byte[encryptedBytes.length];
        for (int i = 0; i < encryptedBytes.length; i++) {
            // Reverse the shift for each byte. Handle negative results by adding 256 if negative.
            decrypted[i] = (byte) ((encryptedBytes[i] - shift) % 256); // This is a very simplistic approach
        }
        logger.debug("Binary data decryption complete. Decrypted size: {} bytes.", decrypted.length);
        return decrypted;
    }
    // --- END NEW METHODS ---
}