package com.vishal.taskMgmt.sharedLib.user.dto;

import com.vishal.taskMgmt.sharedLib.user.entities.UserType;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class AddUsersDTO {
	
	String id;
	
	String name;
	
	String phone;
	
	@Email
	@NotEmpty(message = "Email Id is required")
	String email;
	
	UserType userType;
}
