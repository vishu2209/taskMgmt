package com.vishal.taskMgmt.controllers.auth;

import com.vishal.taskMgmt.sharedLib.user.dto.*;
import org.springframework.data.domain.Page;

public interface UserInterface {
    OtpResponseDTO sendLoginOtp(UserLoginDTO userLoginDTO);
    UserLoginResponseDTO authenticateUser(UserLoginDTO loginDTO);
    UserCreationResponseDTO addUsers(AddUsersDTO addUsersDTO);
    OrganizationCreationResponseDTO addOrganization(AddOrganizationDTO addOrgDTO);
    OtpResponseDTO sendPasswordSetupOtp(String email);
    GenericResponseDTO setPassword(String email, String otp, String newPassword);
    Page<UserResponseDTO> getAllUsers(UserSearchDTO searchDTO);
}