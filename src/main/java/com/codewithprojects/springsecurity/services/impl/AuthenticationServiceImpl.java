package com.codewithprojects.springsecurity.services.impl;


import com.codewithprojects.springsecurity.dto.JwtAuthenticationResponse;
import com.codewithprojects.springsecurity.dto.RefreshTokenRequest;
import com.codewithprojects.springsecurity.dto.SigninRequest;
import com.codewithprojects.springsecurity.dto.SignupRequest;
import com.codewithprojects.springsecurity.entities.Role;
import com.codewithprojects.springsecurity.entities.User;
import com.codewithprojects.springsecurity.repository.UserRepository;
import com.codewithprojects.springsecurity.services.AuthenticationService;
import com.codewithprojects.springsecurity.services.JWTService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JWTService jwtService;

    public User signup(SignupRequest signupRequest) throws Exception {

        if (signupRequest == null || StringUtils.isBlank(signupRequest.getFirstName()) ||
                StringUtils.isBlank(signupRequest.getLastName()) ||
                StringUtils.isBlank(signupRequest.getEmail()) ||
                StringUtils.isBlank(signupRequest.getPassword())) {
            throw new IllegalArgumentException("Signup request is incomplete or invalid.");
        }

        // Check if the email is already in use
       String email = signupRequest.getEmail();
        if (userRepository.findByEmail(email).isPresent()) {
            throw new RuntimeException("User with the same email already exists.");
        }

        // Create a new user
        User user = new User();
        user.setFirstName(signupRequest.getFirstName());
        user.setSecondName(signupRequest.getLastName());
        user.setEmail(email);
        user.setRole(Role.USER);
        user.setPasword(passwordEncoder.encode(signupRequest.getPassword()));

        try {
            return userRepository.save(user);
        } catch (Exception e) {
            // Handle database-related exceptions
            throw new RuntimeException("Failed to create user.", e);
        }
    }


    public JwtAuthenticationResponse signin(SigninRequest signinRequest)
    {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signinRequest.getEmail(),signinRequest.getPassword()));
        var user = userRepository.findByEmail(signinRequest.getEmail()).orElseThrow( ()-> new IllegalArgumentException("Invalid Email or Password"));
        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);
        JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
        jwtAuthenticationResponse.setToken(jwt);
        jwtAuthenticationResponse.setRefreshToken(refreshToken);
        return jwtAuthenticationResponse;
    }

    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest)
    {
        String userEmail = jwtService.extractUserName(refreshTokenRequest.getToken());
        User user = userRepository.findByEmail(userEmail).orElseThrow();

        if(jwtService.isTokenValid(refreshTokenRequest.getToken(),user))
        {
            var jwt = jwtService.generateToken(user);
            JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
            jwtAuthenticationResponse.setToken(jwt);
            jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());
            return jwtAuthenticationResponse;
        }
        return null;

    }

}
