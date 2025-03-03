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
import io.micrometer.common.util.StringUtils;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.time.LocalDateTime;
import java.util.*;

@Service
public class UserService implements UserInterface {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OrganizationRepository organizationRepository;

    @Autowired
    private OtpService otpService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public Map<String, Object> sendLoginOTP(UserLoginDTO userLoginDTO) throws Exception {
        Optional<User> userOptional = userRepository.findByEmailIgnoreCase(userLoginDTO.getEmail().trim());
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (user.isActive()) {
                boolean isPasswordMatches = passwordEncoder.matches(userLoginDTO.getPassword(), user.getPassword());
                if (isPasswordMatches) {
                    String otp = otpService.saveOtp(user, "EMAIL");
                    userLoginDTO.setOtp(otp);
                    Map<String, Object> response = new HashMap<>();
                    response.put("message", "OTP sent successfully");
                    response.put("email", user.getEmail());
                    response.put("otp", otp); // For testing; remove in production
                    return response;
                } else {
                    throw new Exception("Invalid password");
                }
            } else {
                throw new Exception("User account is not active");
            }
        } else {
            throw new Exception("Invalid email");
        }
    }

    public Map<String, Object> authenticateUser(UserLoginDTO loginDTO) throws Exception {
        Optional<User> userOptional = userRepository.findByEmailIgnoreCaseAndActiveTrue(loginDTO.getEmail().trim());
        if (userOptional.isEmpty()) {
            throw new Exception("Invalid email or user not active");
        }
        User user = userOptional.get();
        if (!passwordEncoder.matches(loginDTO.getPassword(), user.getPassword())) {
            throw new Exception("Invalid password");
        }
        UserOTP userOTP = otpService.getUserOTP(user.getId(), loginDTO.getOtp(), "EMAIL");
        if (userOTP == null) {
            throw new Exception("Invalid OTP");
        }
        if (LocalDateTime.now().isAfter(userOTP.getExpiredAt())) {
            throw new Exception("OTP has expired");
        }
        CustomUserDetails userDetails = new CustomUserDetails(user);
        String token = jwtUtil.generateToken(userDetails);
        otpService.deleteOTPAfterUse(userOTP.getId());
        UserLoginResponseDTO userLoginResponseDTO = UserLoginResponseDTO.builder()
            .userId(user.getId())
            .name(user.getName())
            .email(user.getEmail())
            .phone(user.getPhone())
            .userType(user.getUserType())
            .active(user.isActive())
            .accessToken(token)
            .build();
        return Map.of("user", userLoginResponseDTO);
    }

    @Transactional
    public Map<String, Object> addUsersDTO(@Valid AddUsersDTO addUsersDTO) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails)) {
            throw new RuntimeException("Unauthorized: User details not found");
        }
        
        CustomUserDetails currentUser = (CustomUserDetails) authentication.getPrincipal();
        UserType currentUserType = currentUser.getUser().getUserType();
        
        // Check if user is either SUPER_ADMIN or ORG_ADMIN
        if (!UserType.SUPER_ADMIN.equals(currentUserType) && !UserType.ORG_ADMIN.equals(currentUserType)) {
            throw new RuntimeException("Unauthorized: Only SUPER_ADMIN or ORG_ADMIN can add users");
        }
        
        if (addUsersDTO != null) {
            // Validate that only ORG_EMPLOYEE or ORG_USER can be added
            if (!UserType.ORG_EMPLOYEE.equals(addUsersDTO.getUserType()) && 
                !UserType.ORG_USER.equals(addUsersDTO.getUserType())) {
                throw new RuntimeException("Unauthorized: Can only add ORG_EMPLOYEE or ORG_USER");
            }
            
            // Check for duplicate email
            List<User> duplicateUsers = userRepository
                .findByEmailIgnoreCaseAndIdAndActiveTrue(addUsersDTO.getEmail().trim(), addUsersDTO.getId());
            if (!CollectionUtils.isEmpty(duplicateUsers)) {
                throw new RuntimeException("User with this email already exists");
            }
            
            User user;
            Organization organization = null;
            
            // Get current user's organization for ORG_ADMIN
            if (UserType.ORG_ADMIN.equals(currentUserType)) {
                organization = currentUser.getUser().getOrganization();
                if (organization == null) {
                    throw new RuntimeException("ORG_ADMIN must be associated with an organization");
                }
            }
            
            if (StringUtils.isNotEmpty(addUsersDTO.getId())) {
                // Update existing user
                Optional<User> existingUserOptional = userRepository.findById(addUsersDTO.getId());
                if (existingUserOptional.isPresent()) {
                    user = existingUserOptional.get();
                    // Verify the existing user is ORG_EMPLOYEE or ORG_USER
                    if (!UserType.ORG_EMPLOYEE.equals(user.getUserType()) && 
                        !UserType.ORG_USER.equals(user.getUserType())) {
                        throw new RuntimeException("Unauthorized: Can only modify ORG_EMPLOYEE or ORG_USER");
                    }
                    // For ORG_ADMIN, ensure the user belongs to their organization
                    if (UserType.ORG_ADMIN.equals(currentUserType) && 
                        !organization.getId().equals(user.getOrganization().getId())) {
                        throw new RuntimeException("Unauthorized: ORG_ADMIN can only modify users in their own organization");
                    }
                    user.setName(addUsersDTO.getName());
                    user.setEmail(addUsersDTO.getEmail().trim());
                    user.setPhone(addUsersDTO.getPhone());
                    user.setUserType(addUsersDTO.getUserType());
                } else {
                    throw new RuntimeException("User not found for update");
                }
            } else {
                // Create new user
                user = new User();
                user.setName(addUsersDTO.getName());
                user.setEmail(addUsersDTO.getEmail().trim());
                user.setPhone(addUsersDTO.getPhone());
                user.setUserType(addUsersDTO.getUserType());
                user.setActive(true);
                user.setInvitationSent(true);
                user.setPasswordChange(false);
                
                // Set organization
                if (UserType.ORG_ADMIN.equals(currentUserType)) {
                    // ORG_ADMIN can only add to their own organization
                    user.setOrganization(organization);
                } else if (UserType.SUPER_ADMIN.equals(currentUserType)) {
                    // SUPER_ADMIN can add without organization or modify AddUsersDTO to include organizationId
                    user.setOrganization(null); // Or implement organization selection logic
                }
            }
            
            userRepository.save(user);
            Map<String, Object> response = new HashMap<>();
            response.put("message", "User added successfully");
            response.put("userId", user.getId());
            if (user.getOrganization() != null) {
                response.put("organizationId", user.getOrganization().getId());
            }
            return response;
        } else {
            throw new RuntimeException("Invalid input: No fields should be empty");
        }
    }

    public Map<String, Object> sendPasswordSetupOTP(String email) throws Exception {
        Optional<User> userOptional = userRepository.findByEmailIgnoreCase(email.trim());
        if (userOptional.isEmpty()) {
            throw new Exception("User with this email does not exist");
        }
        User user = userOptional.get();
        if (!user.isActive()) {
            throw new Exception("User account is not active");
        }
        String otp = otpService.saveOtp(user, "EMAIL");
        Map<String, Object> response = new HashMap<>();
        response.put("message", "OTP sent successfully for password setup");
        response.put("email", user.getEmail());
        response.put("otp", otp); // For testing; remove in production
        return response;
    }

    public Map<String, Object> setPassword(String email, String otp, String newPassword) throws Exception {
        Optional<User> userOptional = userRepository.findByEmailIgnoreCase(email.trim());
        if (userOptional.isEmpty()) {
            throw new Exception("User with this email does not exist");
        }
        User user = userOptional.get();
        if (!user.isActive()) {
            throw new Exception("User account is not active");
        }
        UserOTP userOTP = otpService.getUserOTP(user.getId(), otp, "EMAIL");
        if (userOTP == null) {
            throw new Exception("Invalid OTP");
        }
        if (LocalDateTime.now().isAfter(userOTP.getExpiredAt())) {
            throw new Exception("OTP has expired");
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordChange(true);
        userRepository.save(user);
        otpService.deleteOTPAfterUse(userOTP.getId());
        return Map.of("message", "Password set successfully");
    }

    @Override
    public Page<UserResponseDTO> getAllUsers(UserDTO userDTO) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails)) {
            throw new RuntimeException("Unauthorized: User details not found");
        }
        CustomUserDetails currentUser = (CustomUserDetails) authentication.getPrincipal();
        if (!UserType.SUPER_ADMIN.equals(currentUser.getUser().getUserType())) {
            throw new RuntimeException("Unauthorized: Only SUPER_ADMIN can fetch all users");
        }
        int page = userDTO.getPage() != null ? userDTO.getPage() : 0;
        int size = userDTO.getSize() != null ? userDTO.getSize() : 10;
        String sortBy = userDTO.getSortBy() != null && !userDTO.getSortBy().isEmpty() ? userDTO.getSortBy() : "email";
        String sortDir = userDTO.getSortDir() != null && !userDTO.getSortDir().isEmpty() ? userDTO.getSortDir() : "asc";
        List<String> validSortFields = Arrays.asList("email", "name", "phone", "userType", "active");
        if (!validSortFields.contains(sortBy)) {
            sortBy = "email";
        }
        Sort sort = Sort.by(Sort.Direction.fromString(sortDir), sortBy);
        Pageable pageable = PageRequest.of(page, size, sort);
        String searchStr = userDTO.getSearchStr() != null ? userDTO.getSearchStr().trim() : null;
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
    public Map<String, Object> addOrganization(AddOrganizationDTO addOrgDTO) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails)) {
            throw new RuntimeException("Unauthorized: User details not found");
        }
        CustomUserDetails currentUser = (CustomUserDetails) authentication.getPrincipal();
        if (!UserType.SUPER_ADMIN.equals(currentUser.getUser().getUserType())) {
            throw new RuntimeException("Unauthorized: Only SUPER_ADMIN can add organizations");
        }

        Optional<Organization> existingOrg = organizationRepository.findByOrgEmail(addOrgDTO.getOrgEmail().trim());
        if (existingOrg.isPresent()) {
            throw new RuntimeException("Organization with this email already exists");
        }

        Optional<User> existingAdmin = userRepository.findByEmailIgnoreCase(addOrgDTO.getAdminEmail().trim());
        if (existingAdmin.isPresent()) {
            throw new RuntimeException("Admin with this email already exists");
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
            .organization(organization)
            .build();

        organization.setOrgAdmin(orgAdmin);

        organizationRepository.save(organization);
        userRepository.save(orgAdmin);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Organization and admin added successfully");
        response.put("orgId", organization.getId());
        response.put("adminId", orgAdmin.getId());
        return response;
    }
}