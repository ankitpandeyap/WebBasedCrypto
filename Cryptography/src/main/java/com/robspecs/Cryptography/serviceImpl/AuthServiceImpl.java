package com.robspecs.Cryptography.serviceImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.Entities.User; // Assuming this is your User entity
import com.robspecs.Cryptography.Enums.Roles; // Assuming this is your Roles enum
import com.robspecs.Cryptography.dto.RegistrationDTO;
import com.robspecs.Cryptography.repository.UserRepository;
import com.robspecs.Cryptography.service.AuthService;


@Service
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final StringRedisTemplate redisTemplate; // Needed for cleaning up OTP/verification keys
    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    @Autowired
    public AuthServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, StringRedisTemplate redisTemplate) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.redisTemplate = redisTemplate;
        logger.debug("AuthServiceImpl initialized");
    }

    @Override
    public User registerNewUser(RegistrationDTO currDTO) {
        String email = currDTO.getEmail();
        logger.info("Registering new user with email: {}", email);

        // If email already exists and is enabled, reject registration
        if (userRepository.existsByEmail(email)) {
            User existingUser = userRepository.findByEmail(email).orElse(null);
            if (existingUser != null && existingUser.isEnabled()) {
                logger.warn("Email already registered and enabled: {}", email);
                throw new RuntimeException("Email already registered!");
            } else {
                logger.debug("Email already exists but is not enabled: {}", email);
            }
        }

        // Check for role (default to USER if not ADMIN)
        Roles role = currDTO.getRole().equalsIgnoreCase("ADMIN") ? Roles.ADMIN : Roles.USER;
        logger.debug("Determined user role: {}", role);

        // Create and save user
        User user = new User();
        user.setName(currDTO.getName());
        user.setEmail(currDTO.getEmail());
        user.setPassword(passwordEncoder.encode(currDTO.getPassword())); // Always encode passwords!
        user.setRole(role);
        user.setUserName(currDTO.getUserName());
        String hashedPasskey = passwordEncoder.encode(currDTO.getPasskey().toString());
        user.setPasskeyHash(hashedPasskey);
        user.setEnabled(true); // User is immediately enabled upon registration
        logger.debug("User object created: {}", user.getUserName());


        // Delete original OTP key from Redis (belt-and-suspenders, as OtpServiceImpl also deletes it)
        redisTemplate.delete(currDTO.getEmail());
        logger.debug("OTP key deleted from Redis for email: {}", currDTO.getEmail());

        // IMPORTANT: Also delete the verification flag after successful registration
        String verifiedFlagKey = currDTO.getEmail() + ":verified";
        redisTemplate.delete(verifiedFlagKey);
        logger.debug("Verification flag key deleted from Redis: {}", verifiedFlagKey);

        User savedUser = userRepository.save(user);
        logger.info("User saved to database with ID: {}", savedUser.getUserId());
        return savedUser;
    }
}
