package com.example.springsecurity.auth;

import java.util.Optional;

public interface ApplicationUserDao {

    /* this interface will make it very easy if we want to switch from one database to another */

    Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
