package com.vishal.taskMgmt.sharedLib.user.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.vishal.taskMgmt.sharedLib.user.entities.User;

public interface UserRepository extends JpaRepository<User, String>{
	
	Optional<User> findByEmail(String email);

}
