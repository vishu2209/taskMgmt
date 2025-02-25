package com.vishal.taskMgmt.controllers.auth;

import org.springframework.data.domain.Page;

import com.vishal.taskMgmt.sharedLib.user.dto.UserDTO;
import com.vishal.taskMgmt.sharedLib.user.entities.User;

public interface UserInterface {
	
	Page<User> getAllUsers(UserDTO userDTO);

}
