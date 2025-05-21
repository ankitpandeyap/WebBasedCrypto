package com.robspecs.Cryptography.serviceImpl;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.PasskeyCacheService;

@Service
public class PasskeyCacheServiceImpl implements PasskeyCacheService {
	 private final RedisTemplate<String, String> redisTemplate;
     
	 
	  
	    public PasskeyCacheServiceImpl(RedisTemplate<String, String> redisTemplate) {
		super();
		this.redisTemplate = redisTemplate;
	}
       
		public void markValidated(String username) {
	        redisTemplate.opsForValue()
	            .set("passkey:validated:" + username, "1", 30, TimeUnit.MINUTES);
	    }

	    public boolean isValidated(String username) {
	        return Boolean.TRUE.equals(
	            redisTemplate.hasKey("passkey:validated:" + username));
	    }

	    public void clearValidated(String username) {
	        redisTemplate.delete("passkey:validated:" + username);
	    }
	}

