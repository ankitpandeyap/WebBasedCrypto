package com.robspecs.Cryptography.service;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.Enums.Roles;

public interface AuthService {
	
	User registerNewUser(String name, String email,String username, String rawPassword, Roles role);

}
