package com.vishal.taskMgmt.sharedLib.user.entities;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.vishal.taskMgmt.sharedLib.user.dto.AddUsersDTO;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Entity
@Table(name = "users")
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
@Data
@FieldDefaults(level = AccessLevel.PRIVATE)
@JsonIgnoreProperties({ "hibernateLazyInitializer", "handler" })
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	String id;

	@Column(name = "name", nullable = false)
	String name;

	@Column(name = "email", unique = true, nullable = true)
	@Email
	String email;

	@Column(name = "phone", nullable = true)
	String phone;

	@Column(name = "password", nullable = true)
	String password;

	@Enumerated(EnumType.STRING)
	UserType userType;
	
	public UserType getUserType() {
	    return userType;
	}

	@Column(name = "active")
	boolean active;

	@Column(name = "invitation")
	boolean isInvitationSent;

	@Column(name = "passwordChange")
	boolean isPasswordChange;
	
	@Column(name = "onboarded")
	boolean isOnboarded;

	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.singleton(new SimpleGrantedAuthority("ROLE_" + userType.name()));
	}

	public User(@Valid AddUsersDTO addUsersDTO) {
		this.name = addUsersDTO.getName();
		this.email = addUsersDTO.getEmail();
		this.phone = addUsersDTO.getPhone();
		this.userType = addUsersDTO.getUserType();
	}
}
