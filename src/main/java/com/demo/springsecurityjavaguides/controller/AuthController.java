package com.demo.springsecurityjavaguides.controller;

import com.demo.springsecurityjavaguides.request.LoginRequest;
import com.demo.springsecurityjavaguides.request.SignupRequest;
import com.demo.springsecurityjavaguides.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    //login rest api
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
        String authenticate = authService.login(loginRequest);
        return ResponseEntity.ok(authenticate);
    }

    //register rest api
    @PostMapping("/signup")
    public ResponseEntity<String> login(@RequestBody SignupRequest signupRequest) {
        String signup = authService.signup(signupRequest);
        return ResponseEntity.ok(signup);
    }

}
