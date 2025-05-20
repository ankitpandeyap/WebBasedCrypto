package com.robspecs.Cryptography.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
class CORSConfig implements WebMvcConfigurer {


	@Value("${cors.allowed.origins}")
	private String [] allowedOrigins;

	@Value("${cors.allowed.methods}")
	private String[] allowedMethods;

	@Value("${cors.allowed.headers}")
	private String allowedHeaders;

	@Value("${cors.allowed.credentials}")
	private boolean allowedCredentials;

	@Override
	public void addCorsMappings(CorsRegistry registry) {
		// TODO Auto-generated method stub
		registry.addMapping("/**")
		.allowCredentials(allowedCredentials)
		.allowedHeaders(allowedHeaders)
        .allowedMethods(allowedMethods)
        .allowedOrigins(allowedOrigins)
        .maxAge(3600)
        .exposedHeaders("Authorization");

	}





}
