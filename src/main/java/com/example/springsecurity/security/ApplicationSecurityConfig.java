package com.example.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.springsecurity.security.ApplicationUserPermission.COURSE_WRITE;
import static com.example.springsecurity.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                /*.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())*/
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {

        UserDetails userPujaPal = User.builder()
                .username("pujapal")
                .password(passwordEncoder.encode("password"))   // this password should be encoded
                //.roles(STUDENT.name())   // ROLE_STUDENT          // role bases authentication
                .authorities(STUDENT.getSimpleGrantedAuthorities()) // permission bases authentication
                .build();

        UserDetails userSushovan = User.builder()
                .username("sushovan")
                .password(passwordEncoder.encode("password123"))
                //.roles(ADMIN.name())    // ROLE_ADMIN             // role bases authentication
                .authorities(ADMIN.getSimpleGrantedAuthorities())   // permission bases authentication
                .build();

        UserDetails userSuvajit = User.builder()
                .username("suvajit")
                .password(passwordEncoder.encode("password123"))
                //.roles(ADMIN_TRAINEE.name())    // ROLE_ADMIN_TRAINEE     // role bases authentication
                .authorities(ADMIN_TRAINEE.getSimpleGrantedAuthorities())   // permission bases authentication
                .build();

        return new InMemoryUserDetailsManager(
                userPujaPal,
                userSushovan,
                userSuvajit
        );
    }
}
