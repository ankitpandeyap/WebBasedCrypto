package com.robspecs.Cryptography.serviceImpl;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;
import com.robspecs.Cryptography.service.RedisPublisher;

@Service
public class RedisPublisherImpl implements RedisPublisher {
	private final RedisTemplate<String, Object> redisTemplate;
	private static final String INBOX_PREFIX = "inbox.";


	public RedisPublisherImpl(@Qualifier("redisJsonTemplate") RedisTemplate<String, Object> redisTemplate) {

		this.redisTemplate = redisTemplate;
	}

	@Override
	public void publishNewMessage(User receiver, MessageSummaryDTO payload) {
		String topic = INBOX_PREFIX + receiver.getUserName();
		redisTemplate.convertAndSend(topic, payload);
	}

}