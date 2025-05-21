package com.robspecs.Cryptography.service;

public interface RedisSubscriber {

	 public void onMessage(Object message, byte[] pattern);
}
