package com.vishal.taskMgmt.controllers.auth;

import com.vishal.taskMgmt.sharedLib.user.dto.AddUsersDTO;
import com.vishal.taskMgmt.sharedLib.user.dto.UserDTO;
import com.vishal.taskMgmt.sharedLib.user.dto.UserLoginDTO;
import com.vishal.taskMgmt.sharedLib.user.entities.User;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.function.Supplier;

@RestController
@RequestMapping(value = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/sendLoginOTP")
    public ResponseEntity<Map<String, Object>> sendLoginOTP(@Valid @RequestBody UserLoginDTO userLoginDTO) {
        return handleRequest(() -> {
            try {
                return userService.sendLoginOTP(userLoginDTO);
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }, HttpStatus.UNAUTHORIZED);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody UserLoginDTO loginDTO) {
        return handleRequest(() -> {
            try {
                return userService.authenticateUser(loginDTO);
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }, HttpStatus.UNAUTHORIZED);
    }

    @PostMapping("/addUsers")
    public ResponseEntity<Map<String, Object>> addUsers(@Valid @RequestBody AddUsersDTO addUsersDTO) {
        return handleRequest(() -> userService.addUsersDTO(addUsersDTO), HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/sendPasswordSetupOTP")
    public ResponseEntity<Map<String, Object>> sendPasswordSetupOTP(@RequestParam String email) {
        return handleRequest(() -> {
            try {
                return userService.sendPasswordSetupOTP(email);
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }, HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/setPassword")
    public ResponseEntity<Map<String, Object>> setPassword(
            @RequestParam String email,
            @RequestParam String otp,
            @RequestParam String newPassword) {
        return handleRequest(() -> {
            try {
                return userService.setPassword(email, otp, newPassword);
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }, HttpStatus.BAD_REQUEST);
    }

    @GetMapping("/GetAllUsers")
    public ResponseEntity<Map<String, Object>> getAllUsers(@Valid @RequestBody UserDTO userDTO) {
        return handleRequest(() -> {
            Page<User> users = userService.getAllUsers(userDTO);
            return Map.of(
                "data", users.getContent(), // List of users
                "totalElements", users.getTotalElements(), // Total number of users
                "totalPages", users.getTotalPages(), // Total pages
                "currentPage", users.getNumber(), // Current page number
                "pageSize", users.getSize(), // Items per page
                "sortBy", userDTO.getSortBy() != null ? userDTO.getSortBy() : "email",
                "sortDir", userDTO.getSortDir() != null ? userDTO.getSortDir() : "asc",
                "searchStr", userDTO.getSearchStr() != null ? userDTO.getSearchStr() : ""
            );
        }, HttpStatus.BAD_REQUEST);
    }

    // Helper method to handle common response pattern
    private ResponseEntity<Map<String, Object>> handleRequest(
            Supplier<Map<String, Object>> serviceCall,
            HttpStatus errorStatus) {
        try {
            return ResponseEntity.ok(serviceCall.get());
        } catch (RuntimeException e) {
            return ResponseEntity.status(errorStatus)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    // Optional: Custom exception handler for validation errors
    @ExceptionHandler(jakarta.validation.ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleValidationErrors(jakarta.validation.ConstraintViolationException ex) {
        Map<String, Object> errorResponse = Map.of(
                "error", "Validation failed",
                "details", ex.getConstraintViolations().stream()
                        .map(cv -> cv.getPropertyPath() + ": " + cv.getMessage())
                        .toList()
        );
        return ResponseEntity.badRequest().body(errorResponse);
    }
}