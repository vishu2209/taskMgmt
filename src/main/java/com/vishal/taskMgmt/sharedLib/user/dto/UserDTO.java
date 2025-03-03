package com.vishal.taskMgmt.sharedLib.user.dto;

import com.vishal.taskMgmt.sharedLib.user.entities.UserType;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.io.Serial;
import java.io.Serializable;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserDTO implements Serializable {
    @Serial
    private static final long serialVersionUID = 5911344621635810620L;

    @NotEmpty(message = "User Id required.") String userId;
    String name;
    @Email @NotEmpty(message = "Email is required") String email;
    String phone;
    String accessToken;
    Boolean active;
    UserType userType;
}