package com.vishal.taskMgmt.sharedLib.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserLoginDTO {
    @NotEmpty(message = "Email is required")
    @Email(message = "Please provide a valid email address")
    private String email;

    @NotEmpty(message = "Password is required")
    private String password;

    private String otp;
}