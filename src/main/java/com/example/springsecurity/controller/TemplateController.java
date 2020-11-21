package com.example.springsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller     // Use @Controller instead of @RestController
@RequestMapping("/")
public class TemplateController {

    @GetMapping("login")
    public String getLoginView() {
        return "login";     // this return type string should be exactly same filename as we have inside the 'templates' package
    }

    @GetMapping("courses")
    public String getCourses() {
        return "courses";
    }
}
