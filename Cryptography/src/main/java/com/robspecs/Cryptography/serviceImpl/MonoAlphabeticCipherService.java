package com.robspecs.Cryptography.serviceImpl;

import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.EncryptionService;

@Service("MONO_ALPHABETIC_CIPHER")
public class MonoAlphabeticCipherService implements EncryptionService {

    private static final Map<Character, Character> ENCRYPT_MAP = new HashMap<>();
    private static final Map<Character, Character> DECRYPT_MAP = new HashMap<>();

    static {
        String plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String cipher = "QWERTYUIOPASDFGHJKLZXCVBNM";

        for (int i = 0; i < plain.length(); i++) {
            ENCRYPT_MAP.put(plain.charAt(i), cipher.charAt(i));
            DECRYPT_MAP.put(cipher.charAt(i), plain.charAt(i));
        }
    }

    @Override
    public String encrypt(String rawMessage, String passkey) {
        StringBuilder encrypted = new StringBuilder();
        for (char ch : rawMessage.toUpperCase().toCharArray()) {
            if (ENCRYPT_MAP.containsKey(ch)) {
                encrypted.append(ENCRYPT_MAP.get(ch));
            } else {
                encrypted.append(ch); // Keep punctuation, numbers unchanged
            }
        }
        return encrypted.toString();
    }

    @Override
    public String decrypt(String encryptedMessage, String passkey) {
        StringBuilder decrypted = new StringBuilder();
        for (char ch : encryptedMessage.toUpperCase().toCharArray()) {
            if (DECRYPT_MAP.containsKey(ch)) {
                decrypted.append(DECRYPT_MAP.get(ch));
            } else {
                decrypted.append(ch);
            }
        }
        return decrypted.toString();
    }
}
