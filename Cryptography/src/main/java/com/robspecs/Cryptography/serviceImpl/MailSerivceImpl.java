package com.robspecs.Cryptography.serviceImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.exceptions.EmailSendingException; // New import for custom exception
import com.robspecs.Cryptography.service.MailService;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

@Service
public class MailSerivceImpl implements MailService {

    private final JavaMailSender mailSender;
    private static final Logger logger = LoggerFactory.getLogger(MailSerivceImpl.class);


    @Autowired
    public MailSerivceImpl(JavaMailSender mailSender) {
        this.mailSender = mailSender;
        logger.debug("MailSerivceImpl initialized");
    }

    @Override
    public void sendOtpEmail(String email, String otp) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(email);
            helper.setSubject("Your OTP Code");

            String htmlContent = "<html><body>"
                    + "<div style='font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto;'>"
                    + "<h2 style='color: #007bff; text-align: center;'>Your One-Time Password</h2>" // Improved heading
                    + "<p style='font-size: 16px; line-height: 1.6; text-align: center;'>Please use the following OTP to complete your registration:</p>"
                    + "<div style='background-color: #e9ecef; padding: 20px; text-align: center; border-radius: 10px; margin-bottom: 20px;'>" // Styled OTP box
                    + "<strong style='font-size: 24px; color: #212529;'>" + otp + "</strong>" // Larger, stronger OTP
                    + "</div>"
                    + "<p style='font-size: 14px; color: #6c757d; text-align: center;'>This OTP is valid for 5 minutes.</p>" // Expiry notice
                    + "<p style='font-size: 14px; color: #6c757d; text-align: center;'>If you did not request this OTP, please ignore this email.</p>"
                    + "</div>"
                    + "</body></html>";

            helper.setText(htmlContent, true);
            mailSender.send(message);
            logger.info("OTP email sent successfully to: {}", email);

        } catch (MessagingException e) {
            logger.error("Error sending OTP email to {}: {}", email, e.getMessage(), e); // Added 'e' to log stack trace
            // Changed to EmailSendingException
            throw new EmailSendingException("Failed to send OTP email", e);
        }
    }
}
