package com.vishal.taskMgmt.controllers.auth;

import com.vishal.taskMgmt.common.services.OtpService;
import com.vishal.taskMgmt.security.CustomUserDetails;
import com.vishal.taskMgmt.security.JwtUtil;
import com.vishal.taskMgmt.sharedLib.user.dto.*;
import com.vishal.taskMgmt.sharedLib.user.entities.Organization;
import com.vishal.taskMgmt.sharedLib.user.entities.User;
import com.vishal.taskMgmt.sharedLib.user.entities.UserOTP;
import com.vishal.taskMgmt.sharedLib.user.entities.UserType;
import com.vishal.taskMgmt.sharedLib.user.repository.OrganizationRepository;
import com.vishal.taskMgmt.sharedLib.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService implements UserInterface {

    private final UserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final OtpService otpService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    public OtpResponseDTO sendLoginOtp(UserLoginDTO userLoginDTO) {
        User user = userRepository.findByEmailIgnoreCase(userLoginDTO.getEmail().trim())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email"));
        if (!user.isActive()) {
            throw new IllegalStateException("User account is not active");
        }
        if (!passwordEncoder.matches(userLoginDTO.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid password");
        }
        String otp = otpService.saveOtp(user, "EMAIL");
        return new OtpResponseDTO("OTP sent successfully", user.getEmail(),otp);
    }

    public UserLoginResponseDTO authenticateUser(UserLoginDTO loginDTO) {
        User user = userRepository.findByEmailIgnoreCaseAndActiveTrue(loginDTO.getEmail().trim())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or user not active"));
        if (!passwordEncoder.matches(loginDTO.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid password");
        }
        UserOTP userOTP = Optional.ofNullable(otpService.getUserOTP(user.getId(), loginDTO.getOtp(), "EMAIL"))
                .orElseThrow(() -> new IllegalArgumentException("Invalid OTP"));
        if (LocalDateTime.now().isAfter(userOTP.getExpiredAt())) {
            throw new IllegalStateException("OTP has expired");
        }
        CustomUserDetails userDetails = new CustomUserDetails(user);
        String token = jwtUtil.generateToken(userDetails);
        otpService.deleteOTPAfterUse(userOTP.getId());
        return UserLoginResponseDTO.builder()
                .userId(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .phone(user.getPhone())
                .userType(user.getUserType())
                .active(user.isActive())
                .accessToken(token)
                .build();
    }

    //kjhkjfe
    
    @Transactional
    public UserCreationResponseDTO addUsers(AddUsersDTO addUsersDTO) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails currentUser = (CustomUserDetails) auth.getPrincipal();
        UserType currentUserType = currentUser.getUser().getUserType();

        if (!List.of(UserType.SUPER_ADMIN, UserType.ORG_ADMIN).contains(currentUserType)) {
            throw new SecurityException("Unauthorized: Only SUPER_ADMIN or ORG_ADMIN can add users");
        }

        if (!List.of(UserType.ORG_EMPLOYEE, UserType.ORG_USER).contains(addUsersDTO.getUserType())) {
            throw new IllegalArgumentException("Unauthorized: Can only add ORG_EMPLOYEE or ORG_USER");
        }

        if (!userRepository.findByEmailIgnoreCaseAndIdNot(addUsersDTO.getEmail().trim(), addUsersDTO.getId()).isEmpty()) {
            throw new IllegalArgumentException("User with this email already exists");
        }

        User user;
        Organization organization = null;

        // Handle organization assignment based on user type
        if (UserType.ORG_ADMIN.equals(currentUserType)) {
            organization = currentUser.getUser().getOrganization();
            if (organization == null) {
                throw new IllegalStateException("ORG_ADMIN must be associated with an organization");
            }
        } else if (UserType.SUPER_ADMIN.equals(currentUserType)) {
            if (addUsersDTO.getOrgId() == null || addUsersDTO.getOrgId().isBlank()) {
                throw new IllegalArgumentException("Organization ID is required when SUPER_ADMIN adds ORG_EMPLOYEE or ORG_USER");
            }
            organization = organizationRepository.findById(addUsersDTO.getOrgId())
                    .orElseThrow(() -> new IllegalArgumentException("Organization not found with ID: " + addUsersDTO.getOrgId()));
        }

        if (addUsersDTO.getId() != null) {
            // Update existing user
            user = userRepository.findById(addUsersDTO.getId())
                    .orElseThrow(() -> new IllegalArgumentException("User not found for update"));
            if (!List.of(UserType.ORG_EMPLOYEE, UserType.ORG_USER).contains(user.getUserType())) {
                throw new SecurityException("Unauthorized: Can only modify ORG_EMPLOYEE or ORG_USER");
            }
            if (UserType.ORG_ADMIN.equals(currentUserType) && !organization.getId().equals(user.getOrganization().getId())) {
                throw new SecurityException("Unauthorized: ORG_ADMIN can only modify users in their own organization");
            }
            // For SUPER_ADMIN, allow updating orgId if provided
            if (UserType.SUPER_ADMIN.equals(currentUserType) && addUsersDTO.getOrgId() != null && !addUsersDTO.getOrgId().isBlank()) {
                user.setOrganization(organization);
            }
        } else {
            // Create new user
            user = User.builder()
                    .active(true)
                    .isInvitationSent(true)
                    .isPasswordChange(false)
                    .isOnboarded(false)
                    .organization(organization) // Always set organization (non-null for ORG_USER/ORG_EMPLOYEE)
                    .build();
        }

        user.setName(addUsersDTO.getName());
        user.setEmail(addUsersDTO.getEmail().trim());
        user.setPhone(addUsersDTO.getPhone());
        user.setUserType(addUsersDTO.getUserType());
        userRepository.save(user);

        return new UserCreationResponseDTO("User added successfully", user.getId(), user.getOrganization().getId());
    }

    public OtpResponseDTO sendPasswordSetupOtp(String email) {
        User user = userRepository.findByEmailIgnoreCase(email.trim())
                .orElseThrow(() -> new IllegalArgumentException("User with this email does not exist"));
        if (!user.isActive()) {
            throw new IllegalStateException("User account is not active");
        }
        String otp = otpService.saveOtp(user, "EMAIL");
        return new OtpResponseDTO("OTP sent successfully for password setup", user.getEmail(),otp);
    }

    public GenericResponseDTO setPassword(String email, String otp, String newPassword) {
        User user = userRepository.findByEmailIgnoreCase(email.trim())
                .orElseThrow(() -> new IllegalArgumentException("User with this email does not exist"));
        if (!user.isActive()) {
            throw new IllegalStateException("User account is not active");
        }
        UserOTP userOTP = Optional.ofNullable(otpService.getUserOTP(user.getId(), otp, "EMAIL"))
                .orElseThrow(() -> new IllegalArgumentException("Invalid OTP"));
        if (LocalDateTime.now().isAfter(userOTP.getExpiredAt())) {
            throw new IllegalStateException("OTP has expired");
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordChange(true);
        userRepository.save(user);
        otpService.deleteOTPAfterUse(userOTP.getId());
        return new GenericResponseDTO("Password set successfully");
    }

    @Override
    public Page<UserResponseDTO> getAllUsers(UserSearchDTO searchDTO) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails currentUser = (CustomUserDetails) auth.getPrincipal();
        if (!UserType.SUPER_ADMIN.equals(currentUser.getUser().getUserType())) {
            throw new SecurityException("Unauthorized: Only SUPER_ADMIN can fetch all users");
        }
        int page = searchDTO.getPage() != null ? searchDTO.getPage() : 0;
        int size = searchDTO.getSize() != null ? searchDTO.getSize() : 10;
        String sortBy = searchDTO.getSortBy() != null && !searchDTO.getSortBy().isEmpty() ? searchDTO.getSortBy() : "email";
        String sortDir = searchDTO.getSortDir() != null && !searchDTO.getSortDir().isEmpty() ? searchDTO.getSortDir() : "asc";
        List<String> validSortFields = Arrays.asList("email", "name", "phone", "userType", "active");
        if (!validSortFields.contains(sortBy)) {
            sortBy = "email";
        }
        Sort sort = Sort.by(Sort.Direction.fromString(sortDir), sortBy);
        Pageable pageable = PageRequest.of(page, size, sort);
        String searchStr = searchDTO.getSearchStr() != null ? searchDTO.getSearchStr().trim() : null;
        return userRepository.findBySearchString(searchStr, pageable)
                .map(user -> UserResponseDTO.builder()
                        .userId(user.getId())
                        .name(user.getName())
                        .email(user.getEmail())
                        .phone(user.getPhone())
                        .userType(user.getUserType())
                        .active(user.isActive())
                        .build());
    }

    @Transactional
    public OrganizationCreationResponseDTO addOrganization(AddOrganizationDTO addOrgDTO) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails currentUser = (CustomUserDetails) auth.getPrincipal();
        if (!UserType.SUPER_ADMIN.equals(currentUser.getUser().getUserType())) {
            throw new SecurityException("Unauthorized: Only SUPER_ADMIN can add organizations");
        }
        if (organizationRepository.findByOrgEmail(addOrgDTO.getOrgEmail().trim()).isPresent()) {
            throw new IllegalArgumentException("Organization with this email already exists");
        }
        if (userRepository.findByEmailIgnoreCase(addOrgDTO.getAdminEmail().trim()).isPresent()) {
            throw new IllegalArgumentException("Admin with this email already exists");
        }
        Organization organization = Organization.builder()
                .orgName(addOrgDTO.getOrgName())
                .orgEmail(addOrgDTO.getOrgEmail().trim())
                .orgContacts(addOrgDTO.getOrgContacts())
                .build();
        User orgAdmin = User.builder()
                .name(addOrgDTO.getAdminName())
                .email(addOrgDTO.getAdminEmail().trim())
                .phone(addOrgDTO.getAdminPhone())
                .userType(UserType.ORG_ADMIN)
                .active(true)
                .isInvitationSent(true)
                .isPasswordChange(false)
                .isOnboarded(false)
                .organization(organization)
                .build();
        organization.setOrgAdmin(orgAdmin);
        organizationRepository.save(organization);
        userRepository.save(orgAdmin);
        return new OrganizationCreationResponseDTO("Organization and admin added successfully", organization.getId(), orgAdmin.getId());
    }
}