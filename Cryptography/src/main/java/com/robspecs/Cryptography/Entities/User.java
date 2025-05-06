package com.robspecs.Cryptography.Entities;

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.robspecs.Cryptography.Enums.Roles;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

@Entity
@Table(name = "users", indexes = { @Index(name = "email_idx", columnList = "email", unique = true) })
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long userId;

	@Column(nullable = false)
	private String name;

	@Column(nullable = false)
	private String email;

	@Column(nullable = false, unique = true)
	private String userName;

	@Column(nullable = false)
	private Roles role;

	@Column(nullable = false)
	private String password;

	private boolean enabled = false; // After OTP verification

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public Roles getRole() {
		return role;
	}

	public void setRole(Roles role) {
		this.role = role;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Long getUserId() {
		return userId;
	}

	public String getPassword() {
		return password;
	}

}
