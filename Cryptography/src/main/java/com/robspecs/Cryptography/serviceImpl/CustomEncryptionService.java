package com.robspecs.Cryptography.serviceImpl;

import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.EncryptionService;

@Service("CUSTOM")
public class CustomEncryptionService implements EncryptionService {

    private static final int SHIFT = 3;

    @Override
    public String encrypt(String rawMessage, String passkey) {
        StringBuilder encrypted = new StringBuilder();
        for (char c : rawMessage.toCharArray()) {
            encrypted.append((char)(c + SHIFT));
        }
        return encrypted.reverse().toString();
    }

    @Override
    public String decrypt(String encryptedMessage, String passkey) {
        StringBuilder reversed = new StringBuilder(encryptedMessage).reverse();
        StringBuilder decrypted = new StringBuilder();
        for (char c : reversed.toString().toCharArray()) {
            decrypted.append((char)(c - SHIFT));
        }
        return decrypted.toString();
    }
}
