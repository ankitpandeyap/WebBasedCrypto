package com.robspecs.Cryptography.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.robspecs.Cryptography.service.MailService;
import com.robspecs.Cryptography.service.OtpService;



import com.robspecs.Cryptography.exceptions.OtpCooldownException;
import com.robspecs.Cryptography.exceptions.EmailSendingException;
import com.robspecs.Cryptography.exceptions.InvalidOtpException;
import com.robspecs.Cryptography.exceptions.TooManyOtpAttemptsException;
import com.robspecs.Cryptography.exceptions.EncryptionDecryptionException; // In case OTP hashing fails

@RestController
@RequestMapping("/api/auth/otp")
public class OtpController {

    private final OtpService otpService;
    private final MailService mailService;
    private static final Logger logger = LoggerFactory.getLogger(OtpController.class);

    public OtpController(OtpService otpService, MailService mailService) {
        this.otpService = otpService;
        this.mailService = mailService;
        logger.debug("OtpController initialized");
    }

    @PostMapping("/request")
    public ResponseEntity<?> requestOtp(@RequestParam String email) {
        logger.info("Received OTP request for email: {}", email);
        try {
            String otp = otpService.generateOtp(email); // This can throw OtpCooldownException or EncryptionDecryptionException
            logger.debug("Generated OTP: {} for email: {}", otp, email);
            mailService.sendOtpEmail(email, otp); // This can throw EmailSendingException
            logger.info("OTP sent to email: {}", email);
            return ResponseEntity.ok("OTP sent to " + email);
        } catch (OtpCooldownException e) {
            logger.warn("OTP request blocked for email {}: {}", email, e.getMessage());
            // @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS) on OtpCooldownException handles status
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(e.getMessage());
        } catch (EmailSendingException e) {
            logger.error("Failed to send OTP email to {}: {}", email, e.getMessage(), e);
            // @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR) on EmailSendingException handles status
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to send OTP email: " + e.getMessage());
        } catch (EncryptionDecryptionException e) { // For cases where OTP encryption fails in OtpService
            logger.error("Failed to generate OTP for email {}: {}", email, e.getMessage(), e);
            // @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR) on EncryptionDecryptionException handles status
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to generate OTP: " + e.getMessage());
        } catch (Exception e) { // Catch any other unexpected exceptions
            logger.error("Unexpected error during OTP request for email {}: {}", email, e.getMessage(), e);
            return ResponseEntity.internalServerError().body("Failed to request OTP: An unexpected error occurred.");
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyOtp(@RequestParam String email, @RequestParam String otp) {
        logger.info("Received OTP verification request for email: {}", email);
        logger.debug("Attempting to verify OTP: {} for email: {}", otp, email);
        try {
            // otpService.validateOtp throws an exception if validation fails,
            // so the 'else' block for isValid is unreachable.
            boolean isValid = otpService.validateOtp(email, otp);
            // If we reach here, it means isValid is true and no exception was thrown.
            logger.info("OTP verified successfully for email: {}", email);
            return ResponseEntity.ok("OTP verified");
        } catch (InvalidOtpException e) {
            logger.warn("OTP verification failed for email {}: {}", email, e.getMessage());
            // @ResponseStatus(HttpStatus.BAD_REQUEST) on InvalidOtpException handles status
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (TooManyOtpAttemptsException e) {
            logger.warn("OTP verification failed for email {}: {}", email, e.getMessage());
            // @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS) on TooManyOtpAttemptsException handles status
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(e.getMessage());
        } catch (EncryptionDecryptionException e) { // In case OTP encryption/hashing fails during validation
            logger.error("OTP verification failed for email {} due to encryption error: {}", email, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("OTP verification failed: " + e.getMessage());
        } catch (Exception e) { // Catch any other unexpected exceptions
            logger.error("Unexpected error during OTP verification for email {}: {}", email, e.getMessage(), e);
            return ResponseEntity.internalServerError().body("OTP verification failed: An unexpected error occurred.");
        }
    }
}
