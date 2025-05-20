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
            String otp = otpService.generateOtp(email);
            logger.debug("Generated OTP: {} for email: {}", otp, email);
            mailService.sendOtpEmail(email, otp);
            logger.info("OTP sent to email: {}", email);
            return ResponseEntity.ok("OTP sent to " + email);
        } catch (Exception e) {
            logger.error("Failed to send OTP to email {}: {}", email, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to send OTP: " + e.getMessage());
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyOtp(@RequestParam String email, @RequestParam String otp) {
        logger.info("Received OTP verification request for email: {}", email);
        logger.debug("Attempting to verify OTP: {} for email: {}", otp, email);
        try {
            boolean isValid = otpService.validateOtp(email, otp);
            if (isValid) {
                logger.info("OTP verified successfully for email: {}", email);
                return ResponseEntity.ok("OTP verified");
            } else {
                logger.warn("Invalid OTP provided for email: {}", email);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid OTP");
            }
        } catch (Exception e) {
            logger.error("OTP verification failed for email {}: {}", email, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("OTP verification failed: " + e.getMessage());
        }
    }
}