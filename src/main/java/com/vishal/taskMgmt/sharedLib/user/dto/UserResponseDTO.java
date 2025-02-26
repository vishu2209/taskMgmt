package com.vishal.taskMgmt.sharedLib.user.dto;

import com.vishal.taskMgmt.sharedLib.user.entities.UserType;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.io.Serial;
import java.io.Serializable;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserResponseDTO implements Serializable {

    @Serial
    private static final long serialVersionUID = 5911344621635810621L;

    String userId;
    String name;
    String email;
    String phone;
    UserType userType;
    Boolean active;
}