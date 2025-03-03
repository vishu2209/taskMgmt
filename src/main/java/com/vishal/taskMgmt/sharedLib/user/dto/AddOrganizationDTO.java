package com.vishal.taskMgmt.sharedLib.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AddOrganizationDTO {
    @NotBlank(message = "Organization name is required")
    private String orgName;

    @NotBlank(message = "Organization email is required")
    @Email(message = "Invalid email format")
    private String orgEmail;

    private String orgContacts;

    @NotBlank(message = "Admin name is required")
    private String adminName;

    @NotBlank(message = "Admin email is required")
    @Email(message = "Invalid email format")
    private String adminEmail;

    private String adminPhone;
}