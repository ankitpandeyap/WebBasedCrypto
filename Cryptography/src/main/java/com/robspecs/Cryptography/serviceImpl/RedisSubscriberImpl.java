package com.robspecs.Cryptography.serviceImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.dto.MessageSummaryDTO;
import com.robspecs.Cryptography.service.SseEmitterService;

@Service
public class RedisSubscriberImpl implements MessageListener {

	private static final Logger log = LoggerFactory.getLogger(RedisSubscriberImpl.class);
	private final SseEmitterService sseEmitterService;
	private final RedisTemplate<String, Object> redisTemplate;

	public RedisSubscriberImpl(SseEmitterService sseEmitterService,
			@Qualifier("redisJsonTemplate") RedisTemplate<String, Object> redisTemplate) { // Only one RedisTemplate
																							// parameter
		this.sseEmitterService = sseEmitterService;
		this.redisTemplate = redisTemplate; // Assign the correctly qualified RedisTemplate
	}

	@Override
	public void onMessage(Message message, byte[] pattern) {
		try {
			// RedisTemplate used GenericJackson2JsonRedisSerializer, so message.getBody()
			// is JSON bytes
			String channel = new String(message.getChannel());
			// Extract username: channel = "inbox.{username}"
			String username = channel.substring("inbox.".length());

			MessageSummaryDTO dto = (MessageSummaryDTO) redisTemplate.getValueSerializer()
					.deserialize(message.getBody());
			if (dto == null) {
				log.warn("Failed to deserialize Redis message body for channel {}. Deserialized DTO was null.",
						channel);
				return; // Stop processing if deserialization fails
			}

			log.info("Received Redis message for {}: {}", username, dto.getMessageId());
			sseEmitterService.sendEvent(username, dto);

		} catch (Exception e) {
			log.error("Error in RedisSubscriber onMessage", e);
		}

	}

}
