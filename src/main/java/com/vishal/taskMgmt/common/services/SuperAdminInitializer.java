package com.vishal.taskMgmt.common.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.vishal.taskMgmt.sharedLib.user.entities.User;
import com.vishal.taskMgmt.sharedLib.user.entities.UserType;
import com.vishal.taskMgmt.sharedLib.user.repository.UserRepository;

@Service
public class SuperAdminInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${superadmin.initialize:true}")
    private boolean initializeSuperAdmin;

    @Override
    public void run(String... args) throws Exception {
        if (initializeSuperAdmin) {
            if (userRepository.findByEmail("taskmgmtadmin2@yopmail.com").isEmpty()) {
                User superAdmin = User.builder()
                        .name("Vishal Yadav")
                        .email("taskmgmtadmin@yopmail.com")
                        .phone("8418985692")
                        .password(passwordEncoder.encode("Test@123"))
                        .userType(UserType.SUPER_ADMIN)
                        .active(true)
                        .build();
                userRepository.save(superAdmin);
                System.out.println("Super Admin created successfully!");
            } else {
                System.out.println("Super Admin already exists.");
            }
        }
    }
}
