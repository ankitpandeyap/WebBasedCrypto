package com.robspecs.Cryptography.service;

import java.util.List;
import java.util.Optional;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.UserDTO;
import com.robspecs.Cryptography.dto.UserProfileDTO;

public interface UserService {
	public List<UserDTO> getAllUsers(User user);

	Optional<User> findByUserName(String userName);

	UserProfileDTO getUserProfile(String username);
}
