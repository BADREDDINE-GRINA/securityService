package com.transformation.securityservice;

import com.transformation.securityservice.security.entities.AppRole;
import com.transformation.securityservice.security.entities.AppUser;
import com.transformation.securityservice.security.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.Collection;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class SecurityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityServiceApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner start(final AccountService accountService){
        return new CommandLineRunner() {
            public void run(String... args) throws Exception {
                accountService.addNewRole(new AppRole(null, "USER"));
                accountService.addNewRole(new AppRole(null, "ADMIN"));
                accountService.addNewRole(new AppRole(null, "COACH"));
                accountService.addNewUser(new AppUser(null,"user1","1343",new ArrayList<>()));
                accountService.addNewUser(new AppUser(null,"user2","1343",new ArrayList<>()));
                accountService.addRoletoUser("user1","USER");
                accountService.addRoletoUser("user2","ADMIN");

            }
        };
    }

}
