package com.example.jwtdemo;

import com.example.jwtdemo.config.JwtProperties;
import com.example.jwtdemo.security.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private static final String SECRET = "pU+WZqWgp4+vmBtuLyu/nTPn5e3bJruE5pMg6pI71ZxDTTli7jPfAoMFuEVfOHCZ";

    private final UserDetails user = User.withUsername("amir").password("x").roles("USER").build();

    private JwtService service(long accessTtlMs) {
        return new JwtService(new JwtProperties(SECRET, "jwt-demo", accessTtlMs, 600_000));
    }

    @Test
    void generatesAndReadsClaims() {
        JwtService s = service(60_000);
        var claims = s.parseAccessToken(s.generateAccessToken(user));
        assertEquals("amir", claims.getSubject());
        assertNotNull(claims.getExpiration());
        assertTrue(claims.getExpiration().after(claims.getIssuedAt()));
    }

    @Test
    void rejectsTamperedToken() {
        JwtService s = service(60_000);
        String token = s.generateAccessToken(user);
        String tampered = token.substring(0, token.length() - 2) + (token.endsWith("A") ? "BB" : "AA");
        assertThrows(JwtException.class, () -> s.parseAccessToken(tampered));
    }

    @Test
    void rejectsExpiredToken() {
        JwtService s = service(-1_000);
        String token = s.generateAccessToken(user);
        assertThrows(ExpiredJwtException.class, () -> s.parseAccessToken(token));
    }

    @Test
    void refreshTokenIsNotAcceptedAsAccessToken() {
        JwtService s = service(60_000);
        String refresh = s.generateRefreshToken(user).token();
        assertThrows(JwtException.class, () -> s.parseAccessToken(refresh));
    }

    @Test
    void accessTokenIsNotAcceptedAsRefreshToken() {
        JwtService s = service(60_000);
        String access = s.generateAccessToken(user);
        assertThrows(JwtException.class, () -> s.parseRefreshToken(access));
    }

    @Test
    void refreshTokenHasJtiAndLongerLifetime() {
        JwtService s = service(60_000);
        var issued = s.generateRefreshToken(user);
        var claims = s.parseRefreshToken(issued.token());
        assertEquals(issued.jti(), claims.getId());
        assertEquals("amir", claims.getSubject());
        assertNull(claims.get("roles"));
    }
}
