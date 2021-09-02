package com.transformation.securityservice.security.service;

import com.transformation.securityservice.security.entities.AppRole;
import com.transformation.securityservice.security.entities.AppUser;

import javax.persistence.Entity;
import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoletoUser(String userEmail,String roleName);
    AppUser loadUserbyEmail(String email);
    List<AppUser> listUsers();
}
