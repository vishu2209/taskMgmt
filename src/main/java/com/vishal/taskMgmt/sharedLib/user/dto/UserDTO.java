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

    @NotEmpty(message = "User Id required.")
    String userId;

    String name;

    @Email
    String email;

    String phone;

    String accessToken;

    Boolean active;

    UserType userType;

    // Pagination and sorting fields
    Integer page; // Page number (default: 0)
    Integer size; // Number of items per page (default: 10)
    String sortBy; // Field to sort by (default: email)
    String sortDir; // Sort direction (asc/desc, default: asc)

    // Search field
    String searchStr; // Search string to filter users by name or email

    // Constructor for basic user information
    public UserDTO(String userId, String name, String email, String phone) {
        this.userId = userId;
        this.name = name;
        this.email = email;
        this.phone = phone;
    }
}