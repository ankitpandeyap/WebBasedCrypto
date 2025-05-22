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

		public RedisPublisherImpl(@Qualifier("redisJsonTemplate") RedisTemplate<String, Object> redisTemplate) {

			this.redisTemplate = redisTemplate;
		}

		@Override
		public void publishNewMessage(User receiver, MessageSummaryDTO payload) {
			String topic = "inbox." + receiver.getUserName();
			redisTemplate.convertAndSend(topic, payload);
		}

	}