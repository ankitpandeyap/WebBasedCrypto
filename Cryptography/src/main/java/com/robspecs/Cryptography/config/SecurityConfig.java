package com.robspecs.Cryptography.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.robspecs.Cryptography.security.CustomUserDetailsService;
import com.robspecs.Cryptography.security.JWTAuthenticationEntryPoint;
import com.robspecs.Cryptography.security.JWTAuthenticationFilter;
import com.robspecs.Cryptography.security.JWTRefreshFilter;
import com.robspecs.Cryptography.security.JWTValidationFilter;
import com.robspecs.Cryptography.service.TokenBlacklistService;
import com.robspecs.Cryptography.utils.JWTUtils;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {



	private final JWTAuthenticationEntryPoint jwtAuthenticationEntryPoint;

	@Autowired
	public SecurityConfig(JWTAuthenticationEntryPoint jwtAuthenticationEntryPoint) {

		this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;



	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(AuthenticationManager authenticationManager, HttpSecurity http,
			JWTUtils jwtUtils, CustomUserDetailsService customUserDetailsService, TokenBlacklistService tokenService) throws Exception {

		JWTAuthenticationFilter authFilter = new JWTAuthenticationFilter(authenticationManager, jwtUtils);

		JWTValidationFilter validationFilter = new JWTValidationFilter(authenticationManager, jwtUtils,
				customUserDetailsService,tokenService);

		JWTRefreshFilter jwtRefreshFilter =  new JWTRefreshFilter(authenticationManager, jwtUtils, customUserDetailsService,tokenService);

		return http.csrf(AbstractHttpConfigurer::disable)
				.cors(withDefaults())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.exceptionHandling(exception -> exception.authenticationEntryPoint(jwtAuthenticationEntryPoint)
						.accessDeniedHandler(accessDeniedHandler()))
				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/api/auth/login", "/api/auth/refresh", "/api/auth/signup",
								"/api/auth/register", "/api/auth/otp/verify", "/api/auth/otp/request")
						.permitAll().anyRequest().authenticated())
				.addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
				.addFilterAfter(validationFilter, JWTAuthenticationFilter.class)
				.addFilterAfter(jwtRefreshFilter,validationFilter.getClass())
				.build();
	}

	@Bean
	public static PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
	    return (request, response, accessDeniedException) -> {
	        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
	        response.setContentType("application/json");
	        response.getWriter().write("{\"error\": \"Access Denied!\"}");
	    };
	}
}