package com.robspecs.Cryptography.security;

import java.util.Collection;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.repository.UserRepository;

@Component
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;
	private final static Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

	@Autowired
	public CustomUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
		logger.debug("loadUserByUsername called for usernameOrEmail: {}", usernameOrEmail);
		User currentUser = userRepository.findByEmailOrUserName(usernameOrEmail).orElseThrow(() -> {
			logger.warn("User not found for email or Username: {}",usernameOrEmail);
			return new UsernameNotFoundException("emailor Username  not found in DB " + usernameOrEmail);
		});
		
		if (currentUser == null) {
			logger.warn("User not found for username or email: {}", usernameOrEmail);
			throw new UsernameNotFoundException("Email/Username not found in DB: " + usernameOrEmail);
		}

		Collection<? extends GrantedAuthority> authorities = Set
				.of(new SimpleGrantedAuthority(currentUser.getRole().toString()));
		logger.debug("User found with authorities: {} for usernameOrEmail: {}", authorities, usernameOrEmail);
		return new org.springframework.security.core.userdetails.User(currentUser.getEmail(), currentUser.getPassword(),
				authorities);

	}
}