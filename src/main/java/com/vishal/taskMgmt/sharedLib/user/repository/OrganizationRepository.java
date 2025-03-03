package com.vishal.taskMgmt.sharedLib.user.repository;

import com.vishal.taskMgmt.sharedLib.user.entities.Organization;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrganizationRepository extends JpaRepository<Organization, String> {
    Optional<Organization> findByOrgEmail(String orgEmail);
}