package com.robspecs.Cryptography.service;

public interface PasswordResetTokenService {
	   public String generateAndStoreToken(String userEmail);
	   public String validateToken(String token);
	void invalidateToken(String token);

}
