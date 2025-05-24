package com.robspecs.Cryptography.service;

import java.io.IOException;

import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

public interface SseEmitterService {
	 public SseEmitter createEmitter(String username) throws IOException;
	  public void sendEvent(String username, Object payload) ;


}
