package com.robspecs.Cryptography.service;

import java.util.List;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.UserDTO;

public interface UserService {
	 public List<UserDTO> getAllUsers(User user);
}
