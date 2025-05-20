package com.robspecs.Cryptography.utils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTUtils {
    private final static Logger logger = LoggerFactory.getLogger(JWTUtils.class);
	private final String SECRET_KEY = "=84167ddacceacc4a4a887f12ae83be81295dad84fa9bb6ee294eee82bfc2";
	private final Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));

	// Generate JWT Token
    public String generateToken(String username, long expiryMinutes) {
    	logger.info("Creating JWT token for username :" + username);
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiryMinutes * 60 * 1000)) //in milliseconds
                .signWith(key,SignatureAlgorithm.HS256)
                .compact();
    }

    public String validateAndExtractUsername(String token) {
        try {
        	logger.info("Token {}  extracting username ", token );
            return Jwts.parserBuilder()
            		 .setSigningKey(key)
                     .build()
                     .parseClaimsJws(token)
                     .getBody()
                     .getSubject();

        } catch (MalformedJwtException m) {
            logger.error(m.getLocalizedMessage());
        }
		return null;
    }




}
