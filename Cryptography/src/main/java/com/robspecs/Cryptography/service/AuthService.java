package com.robspecs.Cryptography.service;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.RegistrationDTO;
import com.robspecs.Cryptography.dto.ResetPasswordRequest;

public interface AuthService {

	User registerNewUser(RegistrationDTO regDTO);
	  void processForgotPassword(String email); // <--- ADD THIS METHOD
	    void resetPassword(ResetPasswordRequest request); // <--- ADD THIS METHOD
	}


