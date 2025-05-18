package com.robspecs.Cryptography.serviceImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.Enums.Roles;
import com.robspecs.Cryptography.dto.RegistrationDTO;
import com.robspecs.Cryptography.repository.UserRepository;
import com.robspecs.Cryptography.service.AuthService;



@Service
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final StringRedisTemplate redisTemplate;

    @Autowired
    public AuthServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, StringRedisTemplate redisTemplate) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public User registerNewUser(RegistrationDTO currDTO) {
        String email= currDTO.getEmail();

        // If email already exists and is enabled, reject registration
        if (userRepository.existsByEmail(email)) {
            User existingUser = userRepository.findByEmail(email).orElse(null);
            if (existingUser != null && existingUser.isEnabled()) {
                throw new RuntimeException("Email already registered!");
            }
        }

        // Check for role (default = CONSUMER if not ADMIN)
        Roles role = currDTO.getRole().equalsIgnoreCase("ADMIN") ? Roles.ADMIN : Roles.USER;

        // Create and save user
        User user = new User();
        user.setName(currDTO.getName());
        user.setEmail(currDTO.getEmail());
        user.setPassword(passwordEncoder.encode(currDTO.getPassword())); // Always encode passwords!
        user.setRole(role);
        user.setUserName(currDTO.getUserName());
        user.setEnabled(true);

        // Delete OTP from Redis after successful registration
        redisTemplate.delete(currDTO.getEmail());

        return userRepository.save(user);
    }
}
