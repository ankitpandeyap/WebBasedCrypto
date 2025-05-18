package com.robspecs.Cryptography.serviceImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.service.MailService;



@Service
public class MailSerivceImpl implements MailService {

	private final JavaMailSender mailSender;


     @Autowired
	public MailSerivceImpl(JavaMailSender mailSender) {
		super();
		this.mailSender = mailSender;
	}



	@Override
	public void sendOtpEmail(String email, String otp) {

		 var msg = new SimpleMailMessage();
	        msg.setTo(email);
	        msg.setSubject("Your OTP Code");
	        msg.setText("Your one-time password is: " + otp +
	                    "\nIt will expire in 5 minutes.");
	        mailSender.send(msg);
	    }

	}


