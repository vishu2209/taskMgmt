package com.vishal.taskMgmt.sharedLib.user.responses;

import com.vishal.taskMgmt.sharedLib.user.entities.UserType;

public class AuthenticationResponse {
    private String jwt;
    private UserType userType;
    private boolean active;
    private String name;
    private String email;

    public AuthenticationResponse(String jwt, UserType userType, boolean active, String name, String email) {
        this.jwt = jwt;
        this.userType = userType;
        this.active = active;
        this.name = name;
        this.email = email;
    }

    // Getters and Setters
    public String getJwt() {
        return jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
    }

    public UserType getUserType() {
        return userType;
    }

    public void setUserType(UserType userType) {
        this.userType = userType;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}