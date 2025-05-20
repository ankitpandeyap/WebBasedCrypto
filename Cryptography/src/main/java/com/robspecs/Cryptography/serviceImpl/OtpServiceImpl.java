package com.robspecs.Cryptography.serviceImpl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.OtpService;

@Service
public class OtpServiceImpl implements OtpService {
    private static SecureRandom secureRandom;
    private final StringRedisTemplate redisTemplate;
    private static final long OTP_EXPIRATION_MINUTES = 5; // OTP expires in 5 minutes
    private static final long COOLDOWN_SECONDS = 60; // Cooldown after requesting OTP
    private static final int MAX_ATTEMPTS = 3; // Max 3 wrong attempts
    private static final long VERIFICATION_FLAG_EXPIRATION_MINUTES = 10; // How long the "verified" flag stays in Redis

    static {
        secureRandom = new SecureRandom();
    }

    public OtpServiceImpl(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate; // Inject RedisTemplate
    }

    @Override
    public String generateOtp(String email) {
        String cooldownKey = email + ":cooldown";
        if (Boolean.TRUE.equals(redisTemplate.hasKey(cooldownKey))) {
            throw new RuntimeException("Please wait " + COOLDOWN_SECONDS + " seconds before requesting a new OTP.");
        }

        String otp = generateSecureOtp();
        String encryptedOtp = encryptOtp(otp);

        // Save encrypted OTP
        redisTemplate.opsForValue().set(email, encryptedOtp, OTP_EXPIRATION_MINUTES, TimeUnit.MINUTES);

        // Set cooldown period
        redisTemplate.opsForValue().set(cooldownKey, "1", COOLDOWN_SECONDS, TimeUnit.SECONDS);

        // Reset attempts counter when a new OTP is generated,
        // so a user starts fresh with attempts for the new OTP.
        String attemptsKey = email + ":attempts";
        redisTemplate.delete(attemptsKey);

        // Also delete any existing verification flag if a new OTP is requested for same email
        String verifiedFlagKey = email + ":verified";
        redisTemplate.delete(verifiedFlagKey);

        return otp;
    }

    @Override
    public boolean validateOtp(String email, String otp) {
        String encryptedStoredOtp = redisTemplate.opsForValue().get(email);

        if (encryptedStoredOtp == null) {
            throw new RuntimeException("Invalid or expired OTP.");
        }

        String attemptsKey = email + ":attempts";
        Integer attempts = Optional.ofNullable(redisTemplate.opsForValue().get(attemptsKey))
                                   .map(Integer::valueOf)
                                   .orElse(0);

        if (attempts >= MAX_ATTEMPTS) {
            throw new RuntimeException("Too many failed attempts. Please try again later.");
        }

        String encryptedEnteredOtp = encryptOtp(otp);

        if (encryptedStoredOtp.equals(encryptedEnteredOtp)) {
            // OTP is correct - clean up current OTP and attempts
            redisTemplate.delete(email);         // Delete the actual OTP
            redisTemplate.delete(attemptsKey);  // Delete the attempts counter

            // SET THE VERIFICATION FLAG IN REDIS
            String verifiedFlagKey = email + ":verified";
            redisTemplate.opsForValue().set(verifiedFlagKey, "true", VERIFICATION_FLAG_EXPIRATION_MINUTES, TimeUnit.MINUTES);

            return true;
        } else {
            // OTP is incorrect - increment attempts and throw exception
            redisTemplate.opsForValue().increment(attemptsKey);
            redisTemplate.expire(attemptsKey, OTP_EXPIRATION_MINUTES, TimeUnit.MINUTES);
            throw new RuntimeException("Invalid OTP.");
        }
    }

    private String generateSecureOtp() {
        int otpNumber = secureRandom.nextInt(1_000_000);
        return String.format("%06d", otpNumber);
    }

    private String encryptOtp(String otp) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(otp.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to encrypt OTP due to missing algorithm", e);
        }
    }
}