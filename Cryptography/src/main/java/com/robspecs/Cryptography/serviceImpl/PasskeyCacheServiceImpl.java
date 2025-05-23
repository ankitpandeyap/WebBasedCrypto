package com.robspecs.Cryptography.serviceImpl;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.PasskeyCacheService;

import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class PasskeyCacheServiceImpl implements PasskeyCacheService {

	private static final Logger log = LoggerFactory.getLogger(PasskeyCacheServiceImpl.class);

	private final RedisTemplate<String, String> redisTemplate;

	public PasskeyCacheServiceImpl(RedisTemplate<String, String> redisTemplate) {
		super();
		this.redisTemplate = redisTemplate;
		log.info("PasskeyCacheServiceImpl initialized with RedisTemplate.");
	}

	@Override
	public void markValidated(String username) {
		String key = "passkey:validated:" + username;
		long timeoutMinutes = 30;
		redisTemplate.opsForValue().set(key, "1", timeoutMinutes, TimeUnit.MINUTES);
		log.debug("Marked passkey as validated for user '{}'. Key: {}, Timeout: {} minutes.", username, key, timeoutMinutes);
	}

	@Override
	public boolean isValidated(String username) {
		String key = "passkey:validated:" + username;
		boolean isValid = Boolean.TRUE.equals(redisTemplate.hasKey(key));
		log.debug("Checking passkey validation status for user '{}'. Key: {}, Is Validated: {}.", username, key, isValid);
		return isValid;
	}

	@Override
	public void clearValidated(String username) {
		String key = "passkey:validated:" + username;
		Boolean deleted = redisTemplate.delete(key);
		if (Boolean.TRUE.equals(deleted)) {
			log.debug("Cleared passkey validation for user '{}'. Key: {}.", username, key);
		} else {
			log.warn("Attempted to clear passkey validation for user '{}', but key {} was not found.", username, key);
		}
	}
}