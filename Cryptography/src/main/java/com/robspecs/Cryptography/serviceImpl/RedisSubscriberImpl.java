package com.robspecs.Cryptography.serviceImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;
import com.robspecs.Cryptography.service.SseEmitterService;

import jakarta.annotation.PostConstruct;

@Service
public class RedisSubscriberImpl {

	private static final Logger log = LoggerFactory.getLogger(RedisSubscriberImpl.class);
	private final SseEmitterService sseEmitterService;
	private final RedisTemplate<String, Object> redisTemplate;

	private final ObjectMapper objectMapper; // Inject ObjectMapper

	public RedisSubscriberImpl(SseEmitterService sseEmitterService,
			@Qualifier("redisJsonTemplate") RedisTemplate<String, Object> redisTemplate, ObjectMapper objectMapper) {
		this.sseEmitterService = sseEmitterService;
		this.redisTemplate = redisTemplate;

		this.objectMapper = objectMapper; // Assign ObjectMapper
		log.info("RedisSubscriberImpl initialized.");
	}

	public void receiveMessage(Object raw) {
		// --- END OF MODIFICATION ---
		MessageSummaryDTO messageSummary = objectMapper.convertValue(raw, MessageSummaryDTO.class);
		try {
			// No more manual deserialization or extracting from raw 'Message' object.
			// The `messageSummary` object is already your DTO!

		
			
			if (messageSummary == null) {
				log.warn("Received null MessageSummaryDTO from Redis. Skipping event processing.");
				return;
			}

			// --- USE THE NEW `receiverUsername` FIELD FROM DTO ---
			String receiverUsername = messageSummary.getReceiverUsername(); // <-- Directly get the receiver's username
			// --- END OF USE ---

			if (receiverUsername == null || receiverUsername.isEmpty()) {
				log.warn(
						"Received message (ID: {}) without a specified receiver username for SSE routing. Skipping event processing.",
						messageSummary.getMessageId());
				return;
			}

			log.info("RedisSubscriberImpl: Received message for user '{}': Message ID = {}", receiverUsername,
					messageSummary.getMessageId());
			sseEmitterService.sendEvent(receiverUsername, messageSummary); // Send the DTO directly
			log.info("RedisSubscriberImpl: Successfully passed message ID {} to SseEmitterService for user {}",
					messageSummary.getMessageId(), receiverUsername);

		} catch (Exception e) {
			log.error("Error in RedisSubscriber processing message for SSE. Message ID: {}. Error: {}",
					messageSummary != null ? messageSummary.getMessageId() : "N/A", e.getMessage(), e);
		}
	}

}
