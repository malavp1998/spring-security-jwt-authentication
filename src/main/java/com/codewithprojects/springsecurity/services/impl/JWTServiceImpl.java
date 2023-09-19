package com.codewithprojects.springsecurity.services.impl;

import com.codewithprojects.springsecurity.entities.User;
import com.codewithprojects.springsecurity.services.JWTService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWTServiceImpl implements JWTService {
    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    @Override
    public String generateRefreshToken(Map<String, Object> extraClaim, UserDetails userDetails) {
        return Jwts.builder().setClaims(extraClaim)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 604800000))
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();
    }



    private <T> T extractClaim(String token, Function<Claims, T> claimResolvers) {
        final Claims claims = extractAllClaims(token);
        return claimResolvers.apply(claims);
    }

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private Key getSigninKey() {
        byte[] key = Decoders.BASE64.decode("fsldfjlejrl3ur2oru23ue0u2030r0r0cjfsdlfjslfjsdlfjl");
        return Keys.hmacShaKeyFor(key);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigninKey()).build().parseClaimsJws(token).getBody();
    }

    public boolean isTokenValid(String token, UserDetails userDetails)
    {
       final String userName = extractUserName(token);
       return userName.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }



    public boolean isTokenExpired(String token)
    {
        return extractClaim(token, Claims :: getExpiration).before( new Date());
    }

}
