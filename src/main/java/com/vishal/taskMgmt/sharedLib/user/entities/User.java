package com.vishal.taskMgmt.sharedLib.user.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.vishal.taskMgmt.sharedLib.user.dto.AddUsersDTO;
import jakarta.persistence.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Entity
@Table(name = "users")
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED) // For JPA
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
	
	@Column(name = "email", unique = true, nullable = false)
	@Email
	String email;
	
	@Column(name = "phone", nullable = true)
	String phone;
	
	@Column(name = "password", nullable = true)
	String password;
	
	@Enumerated(EnumType.STRING)
	UserType userType;
	
	@Column(name = "active")
	boolean active;
	
	@Column(name = "invitation")
	boolean isInvitationSent;
	
	@Column(name = "passwordChange")
	boolean isPasswordChange;
	
	@Column(name = "onboarded")
	boolean isOnboarded;
	
	@ManyToOne
	@JoinColumn(name = "org_id", referencedColumnName = "id")
	Organization organization;

	public User(@Valid AddUsersDTO addUsersDTO) {
		this.name = addUsersDTO.getName();
		this.email = addUsersDTO.getEmail();
		this.phone = addUsersDTO.getPhone();
		this.userType = addUsersDTO.getUserType();
	}
}