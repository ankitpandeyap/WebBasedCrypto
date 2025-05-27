package com.robspecs.Cryptography.utils;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.slf4j.Logger; // Added import for Logger
import org.slf4j.LoggerFactory; // Added import for LoggerFactory
import org.springframework.stereotype.Component;

import com.robspecs.Cryptography.Enums.Algorithm;

@Component
public class KeyGenerator {

    private static final Logger log = LoggerFactory.getLogger(KeyGenerator.class); // Added Logger instance
    private final SecureRandom random = new SecureRandom();

    public KeyGenerator() { // Added constructor for logging
        log.info("KeyGenerator initialized.");
    }

    public String generate(Algorithm algo) {
        log.debug("Attempting to generate key for algorithm: {}", algo); // Debug on method entry
        String generatedKey = null;
        try {
            generatedKey = switch (algo) {
                case AES -> generateAesKey();
                case MONO_ALPHABETIC_CIPHER -> generateMonoKey();
                case CUSTOM -> generateCustomKey(); // custom needs no key, but return placeholder
                // --- START OF ADDED DEFAULT CASE ---
                default -> {
                    log.error("Unsupported algorithm for key generation: {}", algo);
                    throw new IllegalArgumentException("Unsupported algorithm for key generation: " + algo);
                }
                // --- END OF ADDED DEFAULT CASE ---
            };
            log.debug("Key successfully generated for algorithm: {}", algo); // Debug on successful generation
        } catch (Exception e) {
            log.error("Error generating key for algorithm {}: {}", algo, e.getMessage(), e); // Error logging
            throw e; // Re-throw the exception
        }
        // Do NOT log the actual 'generatedKey' at info/debug level.
        return generatedKey;
    }

    private String generateAesKey() {
        log.debug("Generating AES key (16 bytes)."); // Specific debug for AES
        byte[] key = new byte[16];
        random.nextBytes(key);
        // Do NOT log the raw key here.
        return Base64.getEncoder().encodeToString(key);
    }

    private String generateMonoKey() {
        log.debug("Generating Mono-Alphabetic Cipher key (full character set).");

        // Define the complete set of characters to be supported by the cipher
        String UPPERCASE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String LOWERCASE_ALPHABET = "abcdefghijklmnopqrstuvwxyz";
        String NUMBERS = "0123456789";
        // Including common special characters and whitespace, newline, carriage return
        String SPECIAL_CHARACTERS = "!@#$%^&*()_-+={}[]|:;\"'<>,.?/ \r\n";

        // Combine all character sets into one list
        List<Character> allChars = new java.util.ArrayList<>();
        UPPERCASE_ALPHABET.chars().forEach(c -> allChars.add((char) c));
        LOWERCASE_ALPHABET.chars().forEach(c -> allChars.add((char) c));
        NUMBERS.chars().forEach(c -> allChars.add((char) c));
        SPECIAL_CHARACTERS.chars().forEach(c -> allChars.add((char) c));

        // Shuffle the combined list of characters
        Collections.shuffle(allChars, random);

        // Build the shuffled string (which is the actual key/cipher alphabet)
        StringBuilder sb = new StringBuilder();
        allChars.forEach(sb::append);

        return sb.toString();
    }

    private String generateCustomKey() {
        log.debug("Generating CUSTOM (Shift Cipher) key."); // Specific debug for Custom
        // For the simple SHIFT cipher, key is the shift integer as string:
        int shift = random.nextInt(25) + 1; // Shift from 1 to 25
        log.debug("Generated shift value: {}", shift); // It's less sensitive to log the shift value itself
        return String.valueOf(shift);
    }
}