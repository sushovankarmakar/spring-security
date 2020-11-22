package com.example.springsecurity.security;

import com.example.springsecurity.auth.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
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

import java.util.concurrent.TimeUnit;

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
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /*When to use CSRF protection ?
        * Recommendation is to use CSRF protection for any request that could be
        * processed by a browser by normal users.
        * if you're only creating a service that is used by non-browser clients,
        * you likely want to disable CSRF protection
        * */
        // https://docs.spring.io/spring-security/site/docs/current/reference/html5/#csrf

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
                    .passwordParameter("password")
                    .usernameParameter("username")  // parameter name should be same as input type name in login.html
                .and()
                .rememberMe()  // default is 2 weeks
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))    // setting the values to 21 days
                    .key("somethingverysecure")    // we can also provide key to generate the md5 hash of other two values
                    .rememberMeParameter("remember-me") // parameter name should be same as input type name in login.html

                    /*like SESSIONID cookie, remember-me cookie is also stored in the in memory database
                    * we can also store that in postgres or redis db
                    * remember-me cookie contains 3 things - username, expiration time, md5 hash of the above other two values */

                /*  https://stackoverflow.com/questions/23661492/implement-logout-functionality-in-spring-boot
                * https://docs.spring.io/spring-security/site/docs/3.2.4.RELEASE/reference/htmlsingle/#csrf-logout
                * https://docs.spring.io/spring-security/site/docs/4.2.12.RELEASE/reference/htmlsingle/#jc-logout
                * https://www.marcobehler.com/guides/spring-security */

                /* the URL that triggers log out to occur(default is "/logout").
                * if CSRF protection is enabled (default), then the request must also be POST.
                * This means that by default POST"/logout" is required to trigger a log out. If CSRF
                * protection is disabled, then any HTTP method is allowed
                *
                * It is considered best practice to use an HTTP POST on any action that changes state (i.e log out) to
                * protect against CSRF attacks. If you really want to use and HTTP GET, you can use
                * logoutRequestMatcher(AntPathRequestMatcher(logoutUrl, "GET"));
                * */

                .and()
                .logout()   // in the browser's network header tab, we can see that logout is GET request
                    .logoutUrl("/logout")
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")     // deleting all the cookies
                    .logoutSuccessUrl("/login");

    }

    /*@Override
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
    }*/

    /* below two methods are for custom dao provider that we've implemented */

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
