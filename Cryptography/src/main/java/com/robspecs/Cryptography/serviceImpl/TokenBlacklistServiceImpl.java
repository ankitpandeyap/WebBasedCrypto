package com.robspecs.Cryptography.serviceImpl;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.TokenBlacklistService;

@Service
public class TokenBlacklistServiceImpl implements TokenBlacklistService {

	private final StringRedisTemplate redisTemplate;

	public TokenBlacklistServiceImpl(StringRedisTemplate redisTemplate) {
		super();
		this.redisTemplate = redisTemplate;
	}

	public void blacklistToken(String token, long expirationInMinutes) {
		redisTemplate.opsForValue().set(token, "BLACKLISTED", expirationInMinutes, TimeUnit.MINUTES);
	}

	public Boolean isBlacklisted(String token) {
		String value = redisTemplate.opsForValue().get(token);
	    return "BLACKLISTED".equals(value);
	}

}

