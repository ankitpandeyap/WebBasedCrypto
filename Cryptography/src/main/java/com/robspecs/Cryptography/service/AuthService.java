package com.robspecs.Cryptography.service;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.RegistrationDTO;

public interface AuthService {

	User registerNewUser(RegistrationDTO regDTO);


}
