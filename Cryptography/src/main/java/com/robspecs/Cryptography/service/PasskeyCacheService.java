package com.robspecs.Cryptography.service;

public interface PasskeyCacheService {
	 public void markValidated(String username);
	 public boolean isValidated(String username);
	 public void clearValidated(String username);

}
