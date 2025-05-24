package com.robspecs.Cryptography.serviceImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
	private static final Logger log = LoggerFactory.getLogger(RedisPublisherImpl.class);


	public RedisPublisherImpl(@Qualifier("redisJsonTemplate") RedisTemplate<String, Object> redisTemplate) {

		this.redisTemplate = redisTemplate;
	}

	@Override
	public void publishNewMessage(User receiver, MessageSummaryDTO messageSummary) {
	    String channel = "inbox." + receiver.getUserName();
	    log.info("Attempting to publish message ID {} to Redis channel: {}", messageSummary.getMessageId(), channel); // <--- ENSURE THIS LOG EXISTS
	    redisTemplate.convertAndSend(channel, messageSummary);
	    log.info("Message ID {} published to Redis channel: {}", messageSummary.getMessageId(), channel); // <--- AND THIS ONE
	}
}