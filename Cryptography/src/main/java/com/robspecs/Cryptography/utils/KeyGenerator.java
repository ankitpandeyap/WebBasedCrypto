package com.robspecs.Cryptography.utils;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.springframework.stereotype.Component;
import org.slf4j.Logger; // Added import for Logger
import org.slf4j.LoggerFactory; // Added import for LoggerFactory

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
        log.debug("Generating Mono-Alphabetic Cipher key."); // Specific debug for Mono
        List<Character> chars = IntStream.range(0, 26)
                .mapToObj(i -> (char)('A' + i)).collect(Collectors.toList());
        Collections.shuffle(chars, random);
        StringBuilder sb = new StringBuilder();
        chars.forEach(sb::append);
        // Do NOT log the raw key here.
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