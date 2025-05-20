package com.robspecs.Cryptography.serviceImpl;

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

    @Autowired
    public AuthServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, StringRedisTemplate redisTemplate) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public User registerNewUser(RegistrationDTO currDTO) {
        String email = currDTO.getEmail();

        // If email already exists and is enabled, reject registration
        if (userRepository.existsByEmail(email)) {
            User existingUser = userRepository.findByEmail(email).orElse(null);
            if (existingUser != null && existingUser.isEnabled()) {
                throw new RuntimeException("Email already registered!");
            }
        }

        // Check for role (default to USER if not ADMIN)
        Roles role = currDTO.getRole().equalsIgnoreCase("ADMIN") ? Roles.ADMIN : Roles.USER;

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


        // Delete original OTP key from Redis (belt-and-suspenders, as OtpServiceImpl also deletes it)
        redisTemplate.delete(currDTO.getEmail());

        // IMPORTANT: Also delete the verification flag after successful registration
        String verifiedFlagKey = currDTO.getEmail() + ":verified";
        redisTemplate.delete(verifiedFlagKey);

        return userRepository.save(user);
    }
}