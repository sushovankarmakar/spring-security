package com.example.springsecurity.security;

import com.google.common.collect.Sets;
import lombok.Getter;

import java.util.Set;

import static com.example.springsecurity.security.ApplicationUserPermission.*;

@Getter
public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(STUDENT_READ, STUDENT_WRITE, COURSE_READ, COURSE_WRITE));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }
}
