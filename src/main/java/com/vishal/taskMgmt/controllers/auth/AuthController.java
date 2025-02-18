package com.vishal.taskMgmt.controllers.auth;

import com.vishal.taskMgmt.security.JwtUtil;
import com.vishal.taskMgmt.sharedLib.user.requests.AuthenticationRequest;
import com.vishal.taskMgmt.sharedLib.user.responses.AuthenticationResponse;
import com.vishal.taskMgmt.security.CustomUserDetails;
import com.vishal.taskMgmt.security.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authenticationRequest.getUsername(),
                            authenticationRequest.getPassword()
                    )
            );
        } catch (Exception e) {
            throw new Exception("Incorrect username or password", e);
        }
        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        CustomUserDetails customUserDetails = (CustomUserDetails) userDetails; // Safe cast now
        
        final String jwt = jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok(new AuthenticationResponse(
            jwt, 
            customUserDetails.getUser().getUserType(), 
            true, // Assuming all users are active by default
            customUserDetails.getUser().getName(),
            customUserDetails.getUser().getEmail()
        ));
    }
}