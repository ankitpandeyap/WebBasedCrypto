package com.robspecs.Cryptography.serviceImpl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.EncryptionService;

@Service("AES")
public class AESEncryptionService implements EncryptionService {

    // Use a proper cipher transformation: Algorithm/Mode/Padding
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding"; // Recommended: CBC mode
    private static final String ALGORITHM = "AES";
    private static final Logger logger = LoggerFactory.getLogger(AESEncryptionService.class);
    private static final int IV_LENGTH_BYTES = 16; // IV for AES/CBC is always 16 bytes (block size)

    // This method now correctly derives a 128-bit (16-byte) AES key from a string.
    // This derived key can then be used for encryption/decryption.
    // This is distinct from the PBKDF2 key used for the user's primary encryption key.
    // This deriveKey is suitable for deriving keys from arbitrary strings (like your 'passkey'
    // or the 'messageContentEncryptionKey' which is a random string you need to treat as a key).
    private SecretKeySpec deriveKey(String keyString) throws Exception {
        // Log sensitive parts carefully, only first few chars for debugging
        logger.info("Deriving key for string (first 5 chars): {}", keyString.substring(0, Math.min(keyString.length(), 5)));
        byte[] keyBytes;
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        keyBytes = sha.digest(keyString.getBytes("UTF-8")); // SHA-256 always produces 32 bytes
        logger.debug("SHA-256 hash length (before copy): {} bytes", keyBytes.length); // Should be 32
        keyBytes = Arrays.copyOf(keyBytes, 16); // Truncate to 16 bytes for AES-128 (128-bit key)
        logger.debug("Final derived key length (after copy): {} bytes", keyBytes.length); // Should be 16
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    @Override
    public String encrypt(String rawMessage, String keyString) throws Exception {
        logger.debug("Encrypting message using AES with CBC mode");
        // Get the SecretKeySpec from the provided keyString (which might be the message's symmetric key
        // or the user's derived key to encrypt the message's symmetric key).
        SecretKeySpec key = deriveKey(keyString); // **CALLING DERIVEKEY HERE**

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH_BYTES]; // Generate a random IV for each encryption
        secureRandom.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(rawMessage.getBytes(StandardCharsets.UTF_8)); // Ensure UTF-8 for message

        // Prepend IV to the encrypted message before Base64 encoding
        // The format will be: [IV (16 bytes)] + [Ciphertext]
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

        String encryptedMessage = Base64.getEncoder().encodeToString(combined);
        logger.debug("Message encrypted successfully");
        return encryptedMessage;
    }

    @Override
    public String decrypt(String encryptedMessage, String keyString) throws Exception {
        logger.debug("Decrypting message using AES with CBC mode");
        // Get the SecretKeySpec from the provided keyString
        SecretKeySpec key = deriveKey(keyString); // **CALLING DERIVEKEY HERE**

        byte[] decodedBytes = Base64.getDecoder().decode(encryptedMessage);

        // Extract IV from the decoded bytes (first 16 bytes are the IV)
        if (decodedBytes.length < IV_LENGTH_BYTES) {
            logger.error("Decrypted data is too short to contain IV. Length: {}", decodedBytes.length);
            throw new IllegalArgumentException("Encrypted data is malformed: missing IV.");
        }
        byte[] iv = Arrays.copyOfRange(decodedBytes, 0, IV_LENGTH_BYTES);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Extract actual ciphertext (rest of the bytes after IV)
        byte[] cipherText = Arrays.copyOfRange(decodedBytes, IV_LENGTH_BYTES, decodedBytes.length);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(cipherText);

        logger.debug("Message decrypted successfully");
        return new String(decryptedBytes, StandardCharsets.UTF_8); // Ensure UTF-8 for message
    }
}