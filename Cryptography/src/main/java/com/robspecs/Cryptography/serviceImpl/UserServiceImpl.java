package com.robspecs.Cryptography.serviceImpl;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.robspecs.Cryptography.Entities.User;
import com.robspecs.Cryptography.dto.UserDTO;
import com.robspecs.Cryptography.repository.UserRepository;
import com.robspecs.Cryptography.service.UserService;

@Service
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;

	public UserServiceImpl(UserRepository userRepository) {
		super();
		this.userRepository = userRepository;
	}

	@Override
	public List<UserDTO> getAllUsers(User authUser) {
		return userRepository.findAll().stream().filter(user -> !user.getUserName().equals(authUser.getUsername()))
				.map(user -> new UserDTO(user.getUserId(), user.getUserName(), user.getEmail())) // Map to UserDTO

				.collect(Collectors.toList());
	}

}
