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
	private static final long COOLDOWN_SECONDS = 60; // 60 seconds cooldown
	private static final int MAX_ATTEMPTS = 3; // Max 3 wrong attempts
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
			throw new RuntimeException("Please wait 60 seconds before requesting a new OTP.");
		}

		String otp = generateSecureOtp();
		String encryptedOtp = encryptOtp(otp);

		// Save encrypted OTP
		redisTemplate.opsForValue().set(email, encryptedOtp, OTP_EXPIRATION_MINUTES, TimeUnit.MINUTES);

		redisTemplate.opsForValue().set(cooldownKey, "1", COOLDOWN_SECONDS, TimeUnit.SECONDS);

		return otp;
	}

	@Override
	public boolean validateOtp(String email, String otp) {
		String encryptedStoredOtp = redisTemplate.opsForValue().get(email);

		if (encryptedStoredOtp == null) {
			throw new RuntimeException("Invalid or expired OTP.");
		}

		String attemptsKey = email + ":attempts";
		Integer attempts = Optional.ofNullable(redisTemplate.opsForValue().get(attemptsKey)).map(Integer::valueOf)
				.orElse(0);

		if (attempts >= MAX_ATTEMPTS) {
			throw new RuntimeException("Too many failed attempts. Please try again later.");
		}

		String encryptedEnteredOtp = encryptOtp(otp);

		if (encryptedStoredOtp.equals(encryptedEnteredOtp)) {
			redisTemplate.delete(email);
			redisTemplate.delete(attemptsKey);
			redisTemplate.opsForValue().set(email, "1", OTP_EXPIRATION_MINUTES, TimeUnit.MINUTES); // Set expiry
			return true;
		} else {
			redisTemplate.opsForValue().increment(attemptsKey);
			redisTemplate.expire(attemptsKey, OTP_EXPIRATION_MINUTES, TimeUnit.MINUTES);
		    redisTemplate.opsForValue().set(email, "failed");
			throw new RuntimeException("Invalid or expired OTP.");
		}
	}

	private String generateSecureOtp() {
		int otpNumber = secureRandom.nextInt(1_000_000);
		return String.format("%06d", otpNumber);
	}

	// Encrypt OTP using SHA-256
	private String encryptOtp(String otp) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(otp.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(hash);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Failed to encrypt OTP", e);
		}
	}
}