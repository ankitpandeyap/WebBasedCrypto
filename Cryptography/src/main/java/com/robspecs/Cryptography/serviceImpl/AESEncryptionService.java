package com.robspecs.Cryptography.serviceImpl;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.EncryptionService;

@Service("AES")
public class AESEncryptionService implements EncryptionService {

    private static final String ALGORITHM = "AES";

    @Override
    public String encrypt(String rawMessage, String passkey) throws Exception {
        SecretKeySpec key = new SecretKeySpec(passkey.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(rawMessage.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    @Override
    public String decrypt(String encryptedMessage, String passkey) throws Exception {
        SecretKeySpec key = new SecretKeySpec(passkey.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decrypted);
    }
}
