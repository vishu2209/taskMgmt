package com.vishal.taskMgmt.sharedLib.user.repository;

import com.vishal.taskMgmt.sharedLib.user.entities.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByEmailIgnoreCase(String email);
    Optional<User> findByEmailIgnoreCaseAndActiveTrue(String email);
    List<User> findByEmailIgnoreCaseAndIdNot(String email, String id);

    @Query("SELECT u FROM User u WHERE (:searchStr IS NULL OR u.email LIKE %:searchStr% OR u.name LIKE %:searchStr%)")
    Page<User> findBySearchString(String searchStr, Pageable pageable);
	String findByEmail(String string);
}