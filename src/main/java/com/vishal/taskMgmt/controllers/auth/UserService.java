package com.vishal.taskMgmt.controllers.auth;

import com.vishal.taskMgmt.common.services.OtpService;
import com.vishal.taskMgmt.security.CustomUserDetails;
import com.vishal.taskMgmt.security.JwtUtil;
import com.vishal.taskMgmt.sharedLib.user.dto.AddUsersDTO;
import com.vishal.taskMgmt.sharedLib.user.dto.UserDTO;
import com.vishal.taskMgmt.sharedLib.user.dto.UserLoginDTO;
import com.vishal.taskMgmt.sharedLib.user.dto.UserResponseDTO;
import com.vishal.taskMgmt.sharedLib.user.entities.User;
import com.vishal.taskMgmt.sharedLib.user.entities.UserOTP;
import com.vishal.taskMgmt.sharedLib.user.entities.UserType;
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
import org.springframework.util.CollectionUtils;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class UserService implements UserInterface {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private OtpService otpService;

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private PasswordEncoder passwordEncoder;

	// Existing sendLoginOTP method (unchanged)
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
					response.put("otp", otp);
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

	// Existing authenticateUser method (unchanged)
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
		UserDTO userDTO = UserDTO.builder().userId(user.getId()).name(user.getName()).email(user.getEmail())
				.phone(user.getPhone()).userType(user.getUserType()).active(user.isActive()).accessToken(token).build();
		return Map.of("user", userDTO);
	}

	// Fixed addUsersDTO method
	public Map<String, Object> addUsersDTO(@Valid AddUsersDTO addUsersDTO) {
		// Get currently logged-in user
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails)) {
			throw new RuntimeException("Unauthorized: User details not found");
		}
		CustomUserDetails currentUser = (CustomUserDetails) authentication.getPrincipal();
		// Check if the logged-in user is SUPER_ADMIN
		if (!"SUPER_ADMIN".equals(currentUser.getUser().getUserType().name())) { // Fixed getUserType issue
			throw new RuntimeException("Unauthorized: Only SUPER_ADMIN can add users");
		}
		if (addUsersDTO != null) {
			// Check for duplicate email
			List<User> duplicateUsers = userRepository
					.findByEmailIgnoreCaseAndIdAndActiveTrue(addUsersDTO.getEmail().trim(), addUsersDTO.getId());
			if (!CollectionUtils.isEmpty(duplicateUsers)) {
				throw new RuntimeException("User with this email already exists");
			}
			User user;
			if (StringUtils.isNotEmpty(addUsersDTO.getId())) {
				// Update existing user
				Optional<User> existingUserOptional = userRepository.findById(addUsersDTO.getId());
				if (existingUserOptional.isPresent()) {
					user = existingUserOptional.get();
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
				user.setInvitationSent(true); // Set invitation flag true
				user.setPasswordChange(false); // Password not set yet
				// Do not set password here; it will be set via the new API
			}
			// Save user
			userRepository.save(user);
			// Return success response
			return Map.of("message", "User added successfully", "userId", user.getId());
		} else {
			throw new RuntimeException("Invalid input: No fields should be empty");
		}
	}

	// New API: Send OTP for password setup/reset
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

	// New API: Validate OTP and set password
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
		// Set the new password
		user.setPassword(passwordEncoder.encode(newPassword));
		user.setPasswordChange(true); // Mark password as changed
		userRepository.save(user);
		// Delete used OTP
		otpService.deleteOTPAfterUse(userOTP.getId());
		return Map.of("message", "Password set successfully");
	}

	@Override
	public Page<UserResponseDTO> getAllUsers(UserDTO userDTO) {
	    // Get the currently logged-in user from the SecurityContext
	    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
	    if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails)) {
	        throw new RuntimeException("Unauthorized: User details not found");
	    }
	    CustomUserDetails currentUser = (CustomUserDetails) authentication.getPrincipal();
	    // Check if the logged-in user is SUPER_ADMIN
	    if (!UserType.SUPER_ADMIN.equals(currentUser.getUser().getUserType())) {
	        throw new RuntimeException("Unauthorized: Only SUPER_ADMIN can fetch all users");
	    }
	    // Build pagination and sorting parameters
	    int page = userDTO.getPage() != null ? userDTO.getPage() : 0;
	    int size = userDTO.getSize() != null ? userDTO.getSize() : 10;
	    String sortBy = userDTO.getSortBy() != null && !userDTO.getSortBy().isEmpty() ? userDTO.getSortBy() : "email";
	    String sortDir = userDTO.getSortDir() != null && !userDTO.getSortDir().isEmpty() ? userDTO.getSortDir() : "asc";
	    // Validate sortBy field
	    List<String> validSortFields = Arrays.asList("email", "name", "phone", "userType", "active");
	    if (!validSortFields.contains(sortBy)) {
	        sortBy = "email"; // Fallback to default
	    }
	    // Create Sort and Pageable objects
	    Sort sort = Sort.by(Sort.Direction.fromString(sortDir), sortBy);
	    Pageable pageable = PageRequest.of(page, size, sort);
	    // Handle search
	    String searchStr = userDTO.getSearchStr() != null ? userDTO.getSearchStr().trim() : null;
	    // Fetch users and map to UserResponseDTO
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
}