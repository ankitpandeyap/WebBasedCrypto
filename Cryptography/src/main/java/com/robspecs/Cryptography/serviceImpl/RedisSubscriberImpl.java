package com.robspecs.Cryptography.serviceImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.RedisSubscriber;

@Service
public class RedisSubscriberImpl implements RedisSubscriber {

	private static final Logger logger = LoggerFactory.getLogger(RedisSubscriberImpl.class);

	public void onMessage(Object message, byte[] pattern) {
		logger.info("Received Redis message on topic {}: {}", new String(pattern), message);
		// You’ll forward this via SSE in Step 6
	}

}
