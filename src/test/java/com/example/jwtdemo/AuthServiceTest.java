package com.example.jwtdemo;

import com.example.jwtdemo.config.JwtProperties;
import com.example.jwtdemo.security.AuthService;
import com.example.jwtdemo.security.JwtService;
import com.example.jwtdemo.security.RefreshTokenStore;
import com.example.jwtdemo.security.TokenCacheService;
import com.example.jwtdemo.web.TokenResponse;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static org.junit.jupiter.api.Assertions.*;

/** Plain unit test: no Spring context, the AuthenticationManager is a lambda that accepts everyone. */
class AuthServiceTest {

    private static final String SECRET = "pU+WZqWgp4+vmBtuLyu/nTPn5e3bJruE5pMg6pI71ZxDTTli7jPfAoMFuEVfOHCZ";

    private JwtService jwtService;
    private RefreshTokenStore store;
    private AuthService authService;
    private TokenCacheService tokenCacheService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(new JwtProperties(SECRET, "jwt-demo", 60_000, 600_000));
        store = new RefreshTokenStore();

        UserDetails user = User.withUsername("amir").password("x").roles("USER").build();
        var users = new InMemoryUserDetailsManager(user);

        authService = new AuthService(
                auth -> new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()),
                users, jwtService, store, tokenCacheService);
    }

    @Test
    void loginReturnsAccessAndRefreshToken() {
        TokenResponse t = authService.login("amir", "x");
        assertEquals("Bearer", t.tokenType());
        assertEquals("amir", jwtService.parseAccessToken(t.accessToken()).getSubject());
        assertEquals("amir", jwtService.parseRefreshToken(t.refreshToken()).getSubject());
        assertEquals(1, store.size());
    }

    @Test
    void refreshRotatesTheRefreshToken() {
        TokenResponse first = authService.login("amir", "x");
        TokenResponse second = authService.refresh(first.refreshToken());

        assertNotEquals(first.refreshToken(), second.refreshToken());
        assertNotEquals(first.accessToken(), second.accessToken());
        assertEquals(1, store.size());   // old one consumed, new one stored
        // the new access token really works
        assertEquals("amir", jwtService.parseAccessToken(second.accessToken()).getSubject());
    }

    @Test
    void usedRefreshTokenCannotBeUsedAgain() {
        TokenResponse first = authService.login("amir", "x");
        authService.refresh(first.refreshToken());
        assertThrows(JwtException.class, () -> authService.refresh(first.refreshToken()));
    }

    @Test
    void reuseOfOldRefreshTokenRevokesTheWholeFamily() {
        TokenResponse first = authService.login("amir", "x");
        TokenResponse second = authService.refresh(first.refreshToken());

        // attacker (or buggy client) replays the old token ...
        assertThrows(JwtException.class, () -> authService.refresh(first.refreshToken()));
        // ... so the newest token is revoked as well
        assertThrows(JwtException.class, () -> authService.refresh(second.refreshToken()));
        assertEquals(0, store.size());
    }

    @Test
    void logoutRevokesRefreshToken() {
        TokenResponse t = authService.login("amir", "x");
        authService.logout(t.refreshToken());
        assertThrows(JwtException.class, () -> authService.refresh(t.refreshToken()));
    }

    @Test
    void accessTokenCannotBeUsedToRefresh() {
        TokenResponse t = authService.login("amir", "x");
        assertThrows(JwtException.class, () -> authService.refresh(t.accessToken()));
    }
}
