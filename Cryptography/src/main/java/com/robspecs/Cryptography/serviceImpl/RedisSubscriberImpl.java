package com.robspecs.Cryptography.serviceImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;
import com.robspecs.Cryptography.service.SseEmitterService;

@Service
public class RedisSubscriberImpl implements MessageListener {

	private static final Logger log = LoggerFactory.getLogger(RedisSubscriberImpl.class);
	private final SseEmitterService sseEmitterService;

	public RedisSubscriberImpl(SseEmitterService sseEmitterService) {

		this.sseEmitterService = sseEmitterService;
	}

	@Override
	public void onMessage(Message message, byte[] pattern) {
		try {
			// RedisTemplate used GenericJackson2JsonRedisSerializer, so message.getBody()
			// is JSON bytes
			String channel = new String(message.getChannel());
			// Extract username: channel = "inbox.{username}"
			String username = channel.substring("inbox.".length());

			// Deserialize payload
			String json = new String(message.getBody());
			MessageSummaryDTO dto = new ObjectMapper().registerModule(new JavaTimeModule()).readValue(json,
					MessageSummaryDTO.class);

			log.info("Received Redis message for {}: {}", username, dto.getMessageId());
			sseEmitterService.sendEvent(username, dto);

		} catch (Exception e) {
			log.error("Error in RedisSubscriber onMessage", e);
		}

	}

}
