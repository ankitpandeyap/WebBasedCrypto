package com.robspecs.Cryptography.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.robspecs.Cryptography.utils.JWTUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {
     private JWTUtils util;
	 
     @Autowired
     public JWTAuthenticationFilter(JWTUtils util) {
    	 this.util = util;
     }
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		 if(!request.getServletPath().equals("/login")) {
			 doFilter(request, response, filterChain);
			 return;
		 }
		 
		
		 
		 
		
	}

	
	   
}
