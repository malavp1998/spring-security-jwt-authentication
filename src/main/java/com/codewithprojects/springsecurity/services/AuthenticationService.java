package com.codewithprojects.springsecurity.services;

import com.codewithprojects.springsecurity.dto.JwtAuthenticationResponse;
import com.codewithprojects.springsecurity.dto.RefreshTokenRequest;
import com.codewithprojects.springsecurity.dto.SigninRequest;
import com.codewithprojects.springsecurity.dto.SignupRequest;
import com.codewithprojects.springsecurity.entities.User;

public interface AuthenticationService {
    User signup(SignupRequest signupRequest) throws Exception;
     JwtAuthenticationResponse signin(SigninRequest signinRequest);
     JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
