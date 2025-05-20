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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    private final JWTAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Autowired
    public SecurityConfig(JWTAuthenticationEntryPoint jwtAuthenticationEntryPoint) {
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        logger.debug("JWTAuthenticationEntryPoint injected into SecurityConfig");
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        AuthenticationManager authenticationManager = configuration.getAuthenticationManager();
        logger.debug("AuthenticationManager bean created");
        return authenticationManager;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(AuthenticationManager authenticationManager, HttpSecurity http,
                                                 JWTUtils jwtUtils, CustomUserDetailsService customUserDetailsService, TokenBlacklistService tokenService) throws Exception {
        logger.debug("Configuring SecurityFilterChain");

        JWTAuthenticationFilter authFilter = new JWTAuthenticationFilter(authenticationManager, jwtUtils);
        logger.debug("JWTAuthenticationFilter created");

        JWTValidationFilter validationFilter = new JWTValidationFilter(authenticationManager, jwtUtils,
                customUserDetailsService, tokenService);
        logger.debug("JWTValidationFilter created");

        JWTRefreshFilter jwtRefreshFilter = new JWTRefreshFilter(authenticationManager, jwtUtils, customUserDetailsService, tokenService);
        logger.debug("JWTRefreshFilter created");

        return http.csrf(AbstractHttpConfigurer::disable)
                .cors(withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(jwtAuthenticationEntryPoint);
                    logger.debug("AuthenticationEntryPoint set");
                    exception.accessDeniedHandler(accessDeniedHandler());
                    logger.debug("AccessDeniedHandler set");
                })
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/api/auth/login", 
                    		"/api/auth/refresh", 
                    		"/api/auth/signup",
                            "/api/auth/register",
                            "/api/auth/otp/verify", 
                            "/api/auth/otp/request")
                            .permitAll().anyRequest().authenticated();
                    logger.debug("Authorization rules configured");
                })
                .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(validationFilter, JWTAuthenticationFilter.class)
                .addFilterAfter(jwtRefreshFilter, validationFilter.getClass())
                .build();
    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        logger.debug("PasswordEncoder bean created");
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        logger.debug("AccessDeniedHandler bean created");
        return (request, response, accessDeniedException) -> {
            logger.warn("Access denied: {}", accessDeniedException.getMessage());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Access Denied!\"}");
        };
    }
}