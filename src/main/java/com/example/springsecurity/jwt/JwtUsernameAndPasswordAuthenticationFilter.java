package com.example.springsecurity.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

/* to reach to an api or controller layer, a request has to go through filer layer,
but the order of the filters in filter layers are not sequential */

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    /* the job of this class is to verify the credentials. spring security does it by default but
    * we can also override this class by ourselves and have our own implementation */

    /* JWT INTRODUCTION
    * ------------------
    * Imagine we have an authentication server and multiple different application (like ios app, android app,
    * web app, 3rd party app) wants to access auth server to get authenticated for further access of other resources
    *
    * Now if we use basic auth or form based auth implementation then it is not best option for this scenario. Here we
    * need a common way to authenticate all the web app. In this scenario, JSON Web Token comes into picture.
    *
    * JSON Web Token
    * --------------
    * pros:
    * 1. Fast because it is stateless
    * 2. Stateless so it doesn't need to have database or the actual session of that current user.
    *   cause everything is embedded inside the token.
    * 3. Used across many services
    * cons:
    * 1. compromised secret key
    * 2. no visibility to logged in users unlike form based authentication
    *   (unless we implement visibility on top of it)
    * 3. token can be stolen. if it stolen, a hacker can pretend to be a real user.
    *
    *
    * JWT Auth Process (Step by step)
    * ---------------
    * 1. Client sends credentials (username and password)
    * 2. Server validates those credentials, creates and sends token back to the client
    * 3. Now from this onwards, client sends a token for each subsequent request and server validates that token.
    * */

    // https://github.com/jwtk/jjwt


    private final AuthenticationManager authenticationManager;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /* attemptAuthentication method will validate the username and password sent by the client */

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest =
                    new ObjectMapper().readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );

            /* authenticationManager will check that the username exists
            and if yes then it will check password is correct or not */

            Authentication authenticate = authenticationManager.authenticate(authentication);
            return authenticate;

        } catch (IOException ioException) {
            throw new RuntimeException(ioException);
        }
    }

    /* successfulAuthentication method will be invoked after the attemptAuthentication method is successful
    * successfulAuthentication will create a JWT token and send it to client */

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        String secretKey = "securesecuresecuresecuresecuresecuresecuresecure";    // key which will be signed to secure the token

        // create the token
        String token = Jwts.builder()
                .setSubject(authResult.getName())   // name of this principal (current user in our system) like in our case, pujapal, sushovankarmakar or suvajitdey
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2))) // setting the expiration date of this token as 2 weeks
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes())) // key has to be long enough and secure.
                .compact();

        // send the token by adding that to the response header
        response.addHeader("Authorization", "Bearer " + token);
    }
}
