package com.vishal.taskMgmt.sharedLib.user.dto;

import java.io.Serial;
import java.io.Serializable;

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
public class UserDTO implements Serializable{
	
	@Serial
    private static final long serialVersionUID = 5911344621635810620L;

    @NotEmpty(message = "User Id required.")
    String userId;
    
    String name;
    
    @Email
    String email;
    
    String phone;
    
    String accessToken;
    
    Boolean active;
    
    UserType userType;
    
    // Constructor for basic user information
    public UserDTO(String userId, String name, String email, String phone) {
        this.userId = userId;
        this.name = name;
        this.email = email;
        this.phone = phone;
    }
	
}
