package com.transformation.securityservice.security.repositories;

import com.transformation.securityservice.security.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser,Long> {
    AppUser findAppUserByEmail(String Email);
}
