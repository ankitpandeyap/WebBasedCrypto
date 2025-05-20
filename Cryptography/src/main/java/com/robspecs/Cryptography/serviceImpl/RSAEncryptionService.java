package com.robspecs.Cryptography.serviceImpl;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.EncryptionService;

@Service("RSA")
public class RSAEncryptionService implements EncryptionService {

    private static final Logger logger = LoggerFactory.getLogger(RSAEncryptionService.class);

    @Override
    public String encrypt(String rawMessage, String publicKeyStr) throws Exception {
        logger.debug("Encrypting message using RSA");
        try {
            PublicKey publicKey = getPublicKey(publicKeyStr);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(rawMessage.getBytes());
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
            logger.debug("Message encrypted successfully");
            return encryptedMessage;
        } catch (Exception e) {
            logger.error("Error during RSA encryption: {}", e.getMessage());
            throw e; // Re-throw the exception to be handled by the caller
        }
    }

    @Override
    public String decrypt(String encryptedMessage, String privateKeyStr) throws Exception {
        logger.debug("Decrypting message using RSA");
        try {
            PrivateKey privateKey = getPrivateKey(privateKeyStr);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            String decryptedMessage = new String(decryptedBytes);
            logger.debug("Message decrypted successfully");
            return decryptedMessage;
        } catch (Exception e) {
            logger.error("Error during RSA decryption: {}", e.getMessage());
            throw e; // Re-throw the exception
        }
    }

    private PublicKey getPublicKey(String key) throws Exception {
        logger.debug("Getting PublicKey from string");
        try {
            byte[] byteKey = Base64.getDecoder().decode(key);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(spec);
            logger.debug("PublicKey obtained");
            return publicKey;
        } catch (Exception e) {
            logger.error("Error getting PublicKey: {}", e.getMessage());
            throw e;
        }
    }

    private PrivateKey getPrivateKey(String key) throws Exception {
        logger.debug("Getting PrivateKey from string");
        try {
            byte[] byteKey = Base64.getDecoder().decode(key);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(spec);
            logger.debug("PrivateKey obtained");
            return privateKey;
        } catch (Exception e) {
            logger.error("Error getting PrivateKey: {}", e.getMessage());
            throw e;
        }
    }
}
