package com.robspecs.Cryptography.serviceImpl;

import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.Entities.User; // Assuming this is your User entity
import com.robspecs.Cryptography.Enums.Roles; // Assuming this is your Roles enum
import com.robspecs.Cryptography.dto.RegistrationDTO;
import com.robspecs.Cryptography.dto.UserDTO;
import com.robspecs.Cryptography.exceptions.EncryptionDecryptionException;
import com.robspecs.Cryptography.exceptions.UserAlreadyExistsException;
import com.robspecs.Cryptography.repository.UserRepository;
import com.robspecs.Cryptography.service.AuthService;


@Service
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final StringRedisTemplate redisTemplate;
    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    @Value("${security.pbkdf2.iterations:65536}")
    private int pbkdf2Iterations;

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

        if (userRepository.existsByEmail(email)) {
            User existingUser = userRepository.findByEmail(email).orElse(null);
            if (existingUser != null && existingUser.isEnabled()) {
                logger.warn("Email already registered and enabled: {}", email);
                throw new UserAlreadyExistsException("Email already registered!"); // Changed to UserAlreadyExistsException
            } else {
                logger.debug("Email already exists but is not enabled: {}", email);
                // Optionally, you might want to handle re-registration for disabled accounts differently here.
                // For now, we proceed to overwrite if not enabled, which might be the desired behavior.
            }
        }

        Roles role = currDTO.getRole().equalsIgnoreCase("ADMIN") ? Roles.ADMIN : Roles.USER;
        logger.debug("Determined user role: {}", role);

        User user = new User();
        user.setName(currDTO.getName());
        user.setEmail(currDTO.getEmail());
        user.setPassword(passwordEncoder.encode(currDTO.getPassword()));
        user.setRole(role);
        user.setUserName(currDTO.getUserName());

        try {
            SecureRandom random = new SecureRandom();
            byte[] passkeySaltBytes = new byte[16];
            random.nextBytes(passkeySaltBytes);
            String passkeySaltBase64 = Base64.getEncoder().encodeToString(passkeySaltBytes);
            user.setPasskeySalt(passkeySaltBase64);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(currDTO.getPasskey().toCharArray(), passkeySaltBytes, pbkdf2Iterations, 256);
            SecretKey secret = factory.generateSecret(spec);
            byte[] derivedKeyBytes = secret.getEncoded();

            String derivedAesKeyBase64 = Base64.getEncoder().encodeToString(derivedKeyBytes);
            user.setDerivedUserEncryptionKey(derivedAesKeyBase64);

            logger.debug("PBKDF2 derived encryption key for user: {} with {} iterations.", user.getUserName(), pbkdf2Iterations);

        } catch (Exception e) {
            logger.error("Error deriving encryption key for user {}: {}", currDTO.getEmail(), e.getMessage(), e);
            throw new EncryptionDecryptionException("Failed to secure encryption key for user registration.", e); // Changed to EncryptionDecryptionException
        }

        user.setEnabled(true);
        logger.debug("User object created: {}", user.getUserName());

        redisTemplate.delete(currDTO.getEmail());
        logger.debug("OTP key deleted from Redis for email: {}", currDTO.getEmail());

        String verifiedFlagKey = currDTO.getEmail() + ":verified";
        redisTemplate.delete(verifiedFlagKey);
        logger.debug("Verification flag key deleted from Redis: {}", verifiedFlagKey);

        User savedUser = userRepository.save(user);
        logger.info("User saved to database with ID: {}", savedUser.getUserId());
        return savedUser;
    }
    
  
}
