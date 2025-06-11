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

    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String ALGORITHM = "AES";
    private static final Logger logger = LoggerFactory.getLogger(AESEncryptionService.class);
    private static final int IV_LENGTH_BYTES = 16;

    // Initialize SecureRandom once for efficiency and proper seeding
    private final SecureRandom secureRandom = new SecureRandom();

    // Your existing deriveKey method - NO CHANGES HERE
    private SecretKeySpec deriveKey(String keyString) throws Exception {
        logger.info("Deriving key for string (first 5 chars): {}", keyString.substring(0, Math.min(keyString.length(), 5)));
        byte[] keyBytes;
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        keyBytes = sha.digest(keyString.getBytes("UTF-8"));
        logger.debug("SHA-256 hash length (before copy): {} bytes", keyBytes.length);
        keyBytes = Arrays.copyOf(keyBytes, 16);
        logger.debug("Final derived key length (after copy): {} bytes", keyBytes.length);
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    // --- NEW METHOD 1: Encrypt byte array data ---
    @Override
    public byte[] encrypt(byte[] rawBytes, String keyString) throws Exception {
        logger.debug("Encrypting {} bytes of binary data with AES.", rawBytes.length);
        SecretKeySpec secretKey = deriveKey(keyString); // Use your existing deriveKey

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        byte[] iv = new byte[IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv); // Generate a random IV for each encryption
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] encryptedBytes = cipher.doFinal(rawBytes);

        // Prepend IV to the ciphertext for easy storage and retrieval
        // The format will be: [IV (16 bytes)] + [Ciphertext]
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

        logger.debug("Binary data encryption complete. Encrypted size (with IV): {} bytes.", combined.length);
        return combined;
    }

    // --- NEW METHOD 2: Decrypt byte array data ---
    @Override
    public byte[] decrypt(byte[] encryptedBytesWithIv, String keyString) throws Exception {
        logger.debug("Decrypting {} bytes of binary data with AES.", encryptedBytesWithIv.length);
        SecretKeySpec secretKey = deriveKey(keyString); // Use your existing deriveKey

        // Extract IV from the beginning of the encrypted bytes
        if (encryptedBytesWithIv.length < IV_LENGTH_BYTES) {
            logger.error("Encrypted data too short to contain IV. Expected at least {} bytes, got {} bytes.", IV_LENGTH_BYTES, encryptedBytesWithIv.length);
            throw new IllegalArgumentException("Encrypted data is too short to contain the IV.");
        }
        byte[] iv = Arrays.copyOfRange(encryptedBytesWithIv, 0, IV_LENGTH_BYTES);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Extract actual ciphertext (rest of the bytes after IV)
        byte[] cipherText = Arrays.copyOfRange(encryptedBytesWithIv, IV_LENGTH_BYTES, encryptedBytesWithIv.length);
        
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] decryptedBytes = cipher.doFinal(cipherText);
        logger.debug("Binary data decryption complete. Decrypted size: {} bytes.", decryptedBytes.length);
        return decryptedBytes;
    }

    // --- MODIFIED EXISTING STRING METHODS (NOW DELEGATE TO BYTE[] METHODS) ---
    @Override
    public String encrypt(String rawMessage, String keyString) throws Exception {
        logger.debug("Encrypting text message with AES (delegating to byte[] method).");
        byte[] rawBytes = rawMessage.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytesWithIv = encrypt(rawBytes, keyString); // Delegate to the new byte[] encrypt method
        String encodedEncryptedMessage = Base64.getEncoder().encodeToString(encryptedBytesWithIv);
        logger.debug("Text message encryption complete. Encoded length: {} bytes.", encodedEncryptedMessage.length());
        return encodedEncryptedMessage;
    }

    @Override
    public String decrypt(String encryptedMessage, String keyString) throws Exception {
        logger.debug("Decrypting text message with AES (delegating to byte[] method).");
        byte[] encryptedBytesWithIv = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = decrypt(encryptedBytesWithIv, keyString); // Delegate to the new byte[] decrypt method
        String decryptedMessageText = new String(decryptedBytes, StandardCharsets.UTF_8);
        logger.debug("Text message decryption complete. Decrypted length: {} bytes.", decryptedMessageText.length());
        return decryptedMessageText;
    }
}