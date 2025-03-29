package com.demo.springsecurityjavaguides.service;

import com.demo.springsecurityjavaguides.entity.Role;
import com.demo.springsecurityjavaguides.entity.User;
import com.demo.springsecurityjavaguides.repository.RoleRepository;
import com.demo.springsecurityjavaguides.repository.UserRepository;
import com.demo.springsecurityjavaguides.request.LoginRequest;
import com.demo.springsecurityjavaguides.request.SignupRequest;
import com.demo.springsecurityjavaguides.security.JwtTokenProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthService(AuthenticationManager authenticationManager,
                       UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder,
                       JwtTokenProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    //login
    public String login(LoginRequest loginRequest) {
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginRequest.getUsernameOrEmail(),
                loginRequest.getPassword()
        ));

        //generate token
        String token = jwtTokenProvider.generateToken(authenticate);

        //set authentication
        SecurityContextHolder.getContext().setAuthentication(authenticate);

        return token;
    }

    //signup
    public String signup(SignupRequest signupRequest) {
        //check username exists
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            throw new RuntimeException("user already exists");
        }

        //check email exists
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new RuntimeException("user already exists");
        }

        User user = new User();
        user.setName(signupRequest.getName());
        user.setUsername(signupRequest.getUsername());
        user.setEmail(signupRequest.getEmail());
        user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));

        Set<Role> roles = new HashSet<>();
        Role roleUser = roleRepository.findByName("ROLE_USER").get();
        roles.add(roleUser);
        user.setRoles(roles);

        userRepository.save(user);

        return "success";
    }

}
