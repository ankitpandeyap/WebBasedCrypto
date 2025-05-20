package com.robspecs.Cryptography.serviceImpl;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.EncryptionService;

@Service("AES")
public class AESEncryptionService implements EncryptionService {

    private static final String ALGORITHM = "AES";
    private static final Logger logger = LoggerFactory.getLogger(AESEncryptionService.class);

    @Override
    public String encrypt(String rawMessage, String passkey) throws Exception {
        logger.debug("Encrypting message using AES");
        SecretKeySpec key = new SecretKeySpec(passkey.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(rawMessage.getBytes());
        String encryptedMessage = Base64.getEncoder().encodeToString(encrypted);
        logger.debug("Message encrypted successfully");
        return encryptedMessage;
    }

    @Override
    public String decrypt(String encryptedMessage, String passkey) throws Exception {
        logger.debug("Decrypting message using AES");
        SecretKeySpec key = new SecretKeySpec(passkey.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        logger.debug("Message decrypted successfully");
        return new String(decrypted);
    }
}
