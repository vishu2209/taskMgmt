package com.vishal.taskMgmt.controllers.auth;

import com.vishal.taskMgmt.sharedLib.user.dto.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @PostMapping("/send-login-otp")
    public ResponseEntity<OtpResponseDTO> sendLoginOtp(@Valid @RequestBody UserLoginDTO userLoginDTO) {
        OtpResponseDTO response = userService.sendLoginOtp(userLoginDTO);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<UserLoginResponseDTO> login(@Valid @RequestBody UserLoginDTO loginDTO) {
        UserLoginResponseDTO response = userService.authenticateUser(loginDTO);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/addUsers")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ORG_ADMIN')")
    public ResponseEntity<UserCreationResponseDTO> addUsers(@Valid @RequestBody AddUsersDTO addUsersDTO) {
        UserCreationResponseDTO response = userService.addUsers(addUsersDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/organizations")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<OrganizationCreationResponseDTO> addOrganization(@Valid @RequestBody AddOrganizationDTO addOrgDTO) {
        OrganizationCreationResponseDTO response = userService.addOrganization(addOrgDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/send-password-setup-otp")
    public ResponseEntity<OtpResponseDTO> sendPasswordSetupOtp(@RequestParam String email) {
        OtpResponseDTO response = userService.sendPasswordSetupOtp(email);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/set-password")
    public ResponseEntity<GenericResponseDTO> setPassword(
            @RequestParam String email,
            @RequestParam String otp,
            @RequestParam String newPassword) {
        GenericResponseDTO response = userService.setPassword(email, otp, newPassword);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/getUsers")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<PagedResponseDTO<UserResponseDTO>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "email") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir,
            @RequestParam(required = false) String searchStr) {
        UserSearchDTO searchDTO = UserSearchDTO.builder()
                .page(page)
                .size(size)
                .sortBy(sortBy)
                .sortDir(sortDir)
                .searchStr(searchStr)
                .build();
        Page<UserResponseDTO> users = userService.getAllUsers(searchDTO);
        PagedResponseDTO<UserResponseDTO> response = new PagedResponseDTO<>(
                users.getContent(),
                users.getNumber(),
                users.getSize(),
                users.getTotalElements(),
                users.getTotalPages()
        );
        return ResponseEntity.ok(response);
    }
}