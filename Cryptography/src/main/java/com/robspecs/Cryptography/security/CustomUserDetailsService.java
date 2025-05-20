package com.robspecs.Cryptography.security;

import java.util.Collection;
import java.util.Set;

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

	@Autowired
	public CustomUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

		User currentUser = userRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("email not found in DB" + email));
		Collection<? extends GrantedAuthority> authorities = Set
				.of(new SimpleGrantedAuthority(currentUser.getRole().toString()));
		return new org.springframework.security.core.userdetails.User(currentUser.getEmail(), currentUser.getPassword(),
				authorities);

	}

}
