package com.robspecs.Cryptography.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class RegistrationDTO {

	@NotBlank(message = "Name is required")
	private String name;

	@NotBlank(message = "Password is required")
	private String password;

	@NotBlank(message = "Role is required")
	private String role;

	@Email(message = "Invalid email format")
	@NotBlank(message = "Email is required")
	private String email;

	@NotNull(message = "Passkey is required")
	private Integer passkey;

	@NotBlank(message = "Username is required")
	private String userName;

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public Integer getPasskey() {
		return passkey;
	}

	public void setPasskey(Integer passkey) {
		this.passkey = passkey;
	}

}
