package com.example.jwtdemo.security;

import com.example.jwtdemo.web.TokenResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final RefreshTokenStore refreshTokenStore;

    public AuthService(AuthenticationManager authenticationManager,
                       UserDetailsService userDetailsService,
                       JwtService jwtService,
                       RefreshTokenStore refreshTokenStore) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtService = jwtService;
        this.refreshTokenStore = refreshTokenStore;
    }

    /** Checks username/password and issues an access + refresh token pair. */
    public TokenResponse login(String username, String password) {
        var auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));
        return issueTokens((UserDetails) auth.getPrincipal());
    }

    /**
     * Refresh token rotation:
     *  1. verify signature / expiry / type=refresh
     *  2. consume its jti (each refresh token works exactly once)
     *  3. if the jti is unknown the token was already used (or revoked): treat it as theft
     *     and revoke all refresh tokens of that user
     *  4. reload the user (current roles, disabled users are rejected) and issue a NEW pair
     */
    public TokenResponse refresh(String refreshToken) {
        Claims claims = jwtService.parseRefreshToken(refreshToken);
        String username = claims.getSubject();

        if (!refreshTokenStore.consume(claims.getId())) {
            refreshTokenStore.revokeAllForUser(username);
            throw new JwtException("Refresh token already used or revoked");
        }

        UserDetails user = userDetailsService.loadUserByUsername(username);
        return issueTokens(user);
    }

    /** Revokes the given refresh token. Idempotent: unknown/expired tokens are ignored. */
    public void logout(String refreshToken) {
        try {
            Claims claims = jwtService.parseRefreshToken(refreshToken);
            refreshTokenStore.consume(claims.getId());
        } catch (JwtException | IllegalArgumentException ignored) {
            // nothing to revoke
        }
    }

    private TokenResponse issueTokens(UserDetails user) {
        String access = jwtService.generateAccessToken(user);
        IssuedToken refresh = jwtService.generateRefreshToken(user);
        refreshTokenStore.save(refresh.jti(), user.getUsername(), refresh.expiresAt());

        return new TokenResponse(access, refresh.token(), "Bearer",
                jwtService.getAccessTokenExpirationSeconds(),
                jwtService.getRefreshTokenExpirationSeconds());
    }
}
