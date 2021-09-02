package com.transformation.securityservice.security.service;

import com.transformation.securityservice.security.entities.AppRole;
import com.transformation.securityservice.security.entities.AppUser;
import com.transformation.securityservice.security.repositories.AppRoleRepository;
import com.transformation.securityservice.security.repositories.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;

@Service
@Transactional
    public class AccountServiceImpl implements AccountService {

    private AppRoleRepository appRoleRepository;
    private AppUserRepository appUserRepository;

    private PasswordEncoder passwordEncoder;

    public AccountServiceImpl(AppRoleRepository appRoleRepository, AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
        this.appRoleRepository = appRoleRepository;
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public AppUser addNewUser(AppUser appUser) {
        String pw=appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(pw));
        return appUserRepository.save(appUser);
    }

    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    public void addRoletoUser(String userEmail, String roleName) {
        AppUser appUser=appUserRepository.findAppUserByEmail(userEmail);
        AppRole appRole=appRoleRepository.findAppRoleByRoleName(roleName);
        appUser.getAppRoles().add(appRole);


    }

    public AppUser loadUserbyEmail(String email) {

        return appUserRepository.findAppUserByEmail(email);
    }

    public List<AppUser> listUsers() {
        return appUserRepository.findAll();
    }
}
