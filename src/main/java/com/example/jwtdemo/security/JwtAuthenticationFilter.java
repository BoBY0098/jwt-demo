package com.example.jwtdemo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String ERROR_ATTR = "jwt_error";
    private static final String PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final TokenCacheService tokenCacheService;

    public JwtAuthenticationFilter(JwtService jwtService, TokenCacheService tokenCacheService) {
        this.jwtService = jwtService;
        this.tokenCacheService = tokenCacheService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        redisValidation(request, response);

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            Claims claims = jwtService.parseAccessToken(header.substring(PREFIX.length()));

            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                List<?> roles = claims.get(JwtService.ROLES_CLAIM, List.class);
                var authorities = roles == null ? List.<SimpleGrantedAuthority>of()
                        : roles.stream().map(r -> new SimpleGrantedAuthority(String.valueOf(r))).toList();

                var auth = new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        } catch (ExpiredJwtException e) {
            request.setAttribute(ERROR_ATTR, "Access token expired");
        } catch (JwtException | IllegalArgumentException e) {
            request.setAttribute(ERROR_ATTR, "Invalid access token");
        }

        chain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header == null || !header.startsWith(PREFIX)) {
            return null;
        }

        return header.substring(PREFIX.length()).trim();
    }

    private void redisValidation(HttpServletRequest request, HttpServletResponse response) {
        String token = extractToken(request);
        if (token != null) {
            // 1. Check blacklist first
            if (tokenCacheService.isTokenBlacklisted(token)) {
                // reject the request
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            // 2. Optionally check if the token still exists in the "valid" set
            // (useful if you want server-side session control)
            if (!tokenCacheService.isTokenValid(token)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }
    }
}
