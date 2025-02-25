package com.vishal.taskMgmt.sharedLib.user.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.vishal.taskMgmt.sharedLib.user.entities.User;

public interface UserRepository extends JpaRepository<User, String> {
    
    Optional<User> findByEmail(String email);

    Optional<User> findByEmailIgnoreCase(String email);

    Optional<User> findByEmailIgnoreCaseAndActiveTrue(String email);

    @Query("SELECT u FROM User u WHERE LOWER(u.email) = LOWER(:email) AND (:id IS NULL OR u.id != :id) AND u.active = true")
    List<User> findByEmailIgnoreCaseAndIdAndActiveTrue(@Param("email") String email, @Param("id") String id);
    
    @Query("SELECT u FROM User u WHERE (:searchStr IS NULL OR " +
            "LOWER(u.name) LIKE LOWER(CONCAT('%', :searchStr, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :searchStr, '%')))")
    Page<User> findBySearchString(@Param("searchStr") String searchStr, Pageable pageable);
}