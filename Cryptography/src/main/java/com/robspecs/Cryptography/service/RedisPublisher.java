package com.robspecs.Cryptography.service;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.MessageSummaryDTO;

public interface RedisPublisher {
	public void publishNewMessage(User receiver, MessageSummaryDTO payload);
}
