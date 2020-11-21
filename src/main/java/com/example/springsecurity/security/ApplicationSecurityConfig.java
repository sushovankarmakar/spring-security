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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static com.example.springsecurity.security.ApplicationUserPermission.COURSE_WRITE;
import static com.example.springsecurity.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    /* BASIC AUTH
    * 1. we have to include authorization header in every single request
    *   username and password is stored in Base64 encrypted format.
    *   if the authorization header is valid, then 200 OK, if invalid then 401 Unauthorized
    * 2. HTTPS is recommended
    * 3. Simple and fast
    * 4. Disadvantage : can't log out */

    /* FORM BASED AUTH
    * 1. client sends a POST request with username and password
    *   server validates those credentials and return 200 OK along with
    *   a cookie. In this cookie, the SESSIONID is attached to the response.
    *   now any subsequent request, the client instead of sending the username
    *   and password, it sends the SESSIONID. and for each request it is checked that
    *   SESSIONID is validated or not and if it is valid then it sends 200 OK along with request.
    *
    *   SESSIONID  is normally invalid after 30 minutes of inactivity.
    *   and it is stored in an in-memory database. we can use Postgres or Redis for this.
    *
    * 2. Standard in most websites
    * 3. forms (full control on how we want to style our form)
    * 4. can logout
    * 5. HTTPS recommended
    * */

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /*When to use CSRF protection ?
        * Recommendation is to use CSRF protection for any request that could be
        * processed by a browser by normal users.
        * if you're only creating a service that is used by non-browser clients,
        * you likely want to disable CSRF protection
        * */

        http
                .csrf().disable()     // disabling csrf
                /*.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()*/
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
                //.httpBasic(); // basic auth
                .formLogin()   // form based auth
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses", true)
                .and()
                .rememberMe();  // default is 2 weeks
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
