package com.example.springsecurity.auth;

import com.google.common.collect.Lists;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.springsecurity.security.ApplicationUserRole.*;

@Repository("FakeRepo")
public class ApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    public ApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {

        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        STUDENT.getSimpleGrantedAuthorities(),
                        passwordEncoder.encode("password"), "pujapal",
                        true, true, true, true),
                new ApplicationUser(
                        ADMIN.getSimpleGrantedAuthorities(),
                        passwordEncoder.encode("password123"), "sushovan",
                        true, true, true, true),
                new ApplicationUser(
                        ADMIN_TRAINEE.getSimpleGrantedAuthorities(),
                        passwordEncoder.encode("password123"), "suvajit",
                        true, true, true, true)

        );

        return applicationUsers;
    }
}
