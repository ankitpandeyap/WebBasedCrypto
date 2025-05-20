package com.robspecs.Cryptography.controllers;

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

    public OtpController(OtpService otpService, MailService mailService) {
        this.otpService = otpService;
        this.mailService = mailService;
    }

    @PostMapping("/request")
    public ResponseEntity<?> requestOtp(@RequestParam String email) {
        try {
            String otp = otpService.generateOtp(email);
            mailService.sendOtpEmail(email, otp);
            return ResponseEntity.ok("OTP sent to " + email);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to send OTP: " + e.getMessage());
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyOtp(@RequestParam String email, @RequestParam String otp) {
        try {
            boolean isValid = otpService.validateOtp(email, otp);
            if (isValid) {
                return ResponseEntity.ok("OTP verified");
            } else {
                // This 'else' block for 'isValid == false' would only be reached if
                // validateOtp returned false without throwing an exception.
                // Given the current OtpServiceImpl, all validation failures throw an exception,
                // so this path is technically unreachable.
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid OTP (should not be reached)");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("OTP verification failed: " + e.getMessage());
        }
    }
}