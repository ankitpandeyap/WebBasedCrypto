package com.robspecs.Cryptography.serviceImpl;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.EncryptionService;

@Service("MONO_ALPHABETIC_CIPHER")
public class MonoAlphabeticCipherService implements EncryptionService {

    // Maps are no longer static, they are generated per key
    // private static final Map<Character, Character> ENCRYPT_MAP = new HashMap<>();
    // private static final Map<Character, Character> DECRYPT_MAP = new HashMap<>();
    private static final Logger logger = LoggerFactory.getLogger(MonoAlphabeticCipherService.class);

    // Remove static block

    private Map<Character, Character> createEncryptMap(String passkey) {
        Map<Character, Character> map = new HashMap<>();
        String plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        // A very simple way to use the passkey: use its characters for the cipher alphabet
        // This is still not very secure or robust, but it USES THE KEY
        String cipher = generateCipherAlphabet(passkey); // Implement this
        for (int i = 0; i < plain.length(); i++) {
            map.put(plain.charAt(i), cipher.charAt(i));
        }
        return map;
    }

    private Map<Character, Character> createDecryptMap(String passkey) {
        Map<Character, Character> map = new HashMap<>();
        String plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String cipher = generateCipherAlphabet(passkey); // Implement this
        for (int i = 0; i < plain.length(); i++) {
            map.put(cipher.charAt(i), plain.charAt(i));
        }
        return map;
    }

    // Needs a method to generate a cipher alphabet from a passkey
    private String generateCipherAlphabet(String passkey) {
         // This is a simplified example. In a real scenario, you'd use a more robust
         // key expansion/derivation or permutation based on the key.
         // For a true monoalphabetic cipher, you'd likely derive a permutation of the alphabet.
         // For demonstration, let's just use the passkey to shift the alphabet.
         // This is still NOT a secure monoalphabetic cipher, just a way to use the key.
        StringBuilder uniqueChars = new StringBuilder();
        for (char c : passkey.toUpperCase().toCharArray()) {
            if (c >= 'A' && c <= 'Z' && uniqueChars.indexOf(String.valueOf(c)) == -1) {
                uniqueChars.append(c);
            }
        }
        String remaining = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        for (char c : remaining.toCharArray()) {
            if (uniqueChars.indexOf(String.valueOf(c)) == -1) {
                uniqueChars.append(c);
            }
        }
        return uniqueChars.toString();
    }

    @Override
    public String encrypt(String rawMessage, String passkey) {
        logger.debug("Encrypting message using MonoAlphabetic Cipher with key");
        Map<Character, Character> encryptMap = createEncryptMap(passkey); // Create map using the provided key
        StringBuilder encrypted = new StringBuilder();
        String upperCaseMessage = rawMessage.toUpperCase();
        for (char ch : upperCaseMessage.toCharArray()) {
            if (encryptMap.containsKey(ch)) {
                encrypted.append(encryptMap.get(ch));
            } else {
                encrypted.append(ch);
            }
        }
        String encryptedMessage = encrypted.toString();
        logger.debug("Message encrypted successfully");
        return encryptedMessage;
    }

    @Override
    public String decrypt(String encryptedMessage, String passkey) {
        logger.debug("Decrypting message using MonoAlphabetic Cipher with key");
        Map<Character, Character> decryptMap = createDecryptMap(passkey); // Create map using the provided key
        StringBuilder decrypted = new StringBuilder();
        String upperCaseMessage = encryptedMessage.toUpperCase();
        for (char ch : upperCaseMessage.toCharArray()) {
            if (decryptMap.containsKey(ch)) {
                decrypted.append(decryptMap.get(ch));
            } else {
                decrypted.append(ch);
            }
        }
        String decryptedMessage = decrypted.toString();
        logger.debug("Message decrypted successfully");
        return decryptedMessage;
    }
}