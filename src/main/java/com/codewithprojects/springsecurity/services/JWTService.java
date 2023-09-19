package com.codewithprojects.springsecurity.services;

import com.codewithprojects.springsecurity.entities.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;

public interface JWTService {

    String extractUserName(String token);

    String generateToken(UserDetails userDetails);

    boolean isTokenValid(String token, UserDetails userDetails);

    String generateRefreshToken(Map<String, Object> extractClaim, UserDetails userDetails);
}
