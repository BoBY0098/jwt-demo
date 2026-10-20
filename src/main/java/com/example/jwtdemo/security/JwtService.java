package com.example.jwtdemo.security;

import com.example.jwtdemo.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
public class JwtService {

    public static final String TYPE_CLAIM = "type";
    public static final String ACCESS = "access";
    public static final String REFRESH = "refresh";
    public static final String ROLES_CLAIM = "roles";

    private final JwtProperties props;
    private final SecretKey key;

    public JwtService(JwtProperties props) {
        this.props = props;
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(props.secret()));
    }

    // ------------------------------------------------------------------ generate

    /** Short-lived access token. Carries the roles so the API needs no DB lookup. */
    public String generateAccessToken(UserDetails user) {
        long now = System.currentTimeMillis();
        List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())          // jti
                .issuer(props.issuer())                    // iss
                .subject(user.getUsername())               // sub
                .claim(TYPE_CLAIM, ACCESS)
                .claim(ROLES_CLAIM, roles)
                .issuedAt(new Date(now))                   // iat
                .expiration(new Date(now + props.accessTokenExpirationMs())) // exp
                .signWith(key)
                .compact();
    }

    /**
     * Long-lived refresh token. It has no roles: they are reloaded from the user
     * store when the token is used. Its jti is tracked server-side (see RefreshTokenStore)
     * so it can be rotated and revoked.
     */
    public IssuedToken generateRefreshToken(UserDetails user) {
        long now = System.currentTimeMillis();
        String jti = UUID.randomUUID().toString();
        Date exp = new Date(now + props.refreshTokenExpirationMs());

        String token = Jwts.builder()
                .id(jti)
                .issuer(props.issuer())
                .subject(user.getUsername())
                .claim(TYPE_CLAIM, REFRESH)
                .issuedAt(new Date(now))
                .expiration(exp)
                .signWith(key)
                .compact();
        return new IssuedToken(token, jti, exp.toInstant());
    }

    // ------------------------------------------------------------------ parse

    /**
     * Verifies signature, issuer and expiration, then returns the claims.
     * Throws a JwtException subclass (ExpiredJwtException, SignatureException,
     * MalformedJwtException, ...) when the token is not valid.
     */
    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .requireIssuer(props.issuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /** Valid token AND type == access. A refresh token is rejected here. */
    public Claims parseAccessToken(String token) {
        return parseWithType(token, ACCESS, "Not an access token");
    }

    /** Valid token AND type == refresh. An access token is rejected here. */
    public Claims parseRefreshToken(String token) {
        return parseWithType(token, REFRESH, "Not a refresh token");
    }

    private Claims parseWithType(String token, String expectedType, String errorMessage) {
        Claims claims = parseClaims(token);
        if (!expectedType.equals(claims.get(TYPE_CLAIM, String.class))) {
            throw new JwtException(errorMessage);
        }
        return claims;
    }

    public long getAccessTokenExpirationSeconds() {
        return props.accessTokenExpirationMs() / 1000;
    }

    public long getRefreshTokenExpirationSeconds() {
        return props.refreshTokenExpirationMs() / 1000;
    }
}
