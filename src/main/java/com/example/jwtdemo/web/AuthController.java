package com.example.jwtdemo.web;

import com.example.jwtdemo.security.AuthService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            return ResponseEntity.ok(authService.login(request.username(), request.password()));
        } catch (AuthenticationException e) {
            return unauthorized("Bad username or password");
        }
    }

    /** Exchanges a valid refresh token for a NEW access + refresh token (rotation). */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody RefreshRequest request) {
        try {
            return ResponseEntity.ok(authService.refresh(request.refreshToken()));
        } catch (ExpiredJwtException e) {
            return unauthorized("Refresh token expired");
        } catch (JwtException | UsernameNotFoundException | IllegalArgumentException e) {
            return unauthorized("Invalid refresh token");
        }
    }

    /** Revokes the refresh token. The (short-lived) access token simply expires on its own. */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshRequest request) {
        authService.logout(request.refreshToken());
        return ResponseEntity.noContent().build();
    }

    private ResponseEntity<Map<String, Object>> unauthorized(String message) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("status", 401, "message", message));
    }
}
