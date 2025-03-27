package com.demo.springsecurityjavaguides.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping
    public String hello() {
        return "Hello World";
    }

    @GetMapping("/user")
    public String user() {
        return "welcome user";
    }

    @GetMapping("/admin")
    public String admin() {
        return "welcome admin";
    }

}
