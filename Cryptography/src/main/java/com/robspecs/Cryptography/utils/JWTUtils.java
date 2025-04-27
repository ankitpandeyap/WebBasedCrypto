package com.robspecs.Cryptography.utils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTUtils {
	private final String SECRET_KEY = "=84167ddacceacc4a4a887f12ae83be81295dad84fa9bb6ee294eee82bfc2";
	private final Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
	
	// Generate JWT Token
    public String generateToken(String username, long expiryMinutes) {
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiryMinutes * 60 * 1000)) //in milliseconds
                .signWith(key)
                .compact();
    }

	
	

}
