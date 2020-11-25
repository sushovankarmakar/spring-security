package com.example.springsecurity.jwt;

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
}
