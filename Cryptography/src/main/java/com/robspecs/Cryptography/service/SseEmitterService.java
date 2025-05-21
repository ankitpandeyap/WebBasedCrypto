package com.robspecs.Cryptography.service;

import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

public interface SseEmitterService {
	 public SseEmitter createEmitter(String username);
	  public void sendEvent(String username, Object payload) ;
	  
	
}
