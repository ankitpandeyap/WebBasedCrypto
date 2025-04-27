package com.robspecs.Cryptography.Entities;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class CustomUser  {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long userId;
    
	@Column(nullable = false)
	private String name;
    
	@Column(nullable = false)
	private String email;
    
	@Column(nullable = false,unique = true)
	private String userName;
	
	@Column(nullable = false)
	private String role;	
	
	@Column(nullable = false)
	private String password;
	
    public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
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

public CustomUser() {}


}
