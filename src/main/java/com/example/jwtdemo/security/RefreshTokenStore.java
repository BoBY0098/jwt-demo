package com.example.jwtdemo.security;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Server-side record of the refresh tokens that are currently valid (keyed by jti).
 * A refresh token is only accepted if its jti is still here, which is what makes
 * rotation, logout and reuse detection possible.
 *
 * In-memory for the demo: it is lost on restart and not shared between instances.
 * In a real application back this with a database or Redis (TTL = token expiry).
 */
@Component
public class RefreshTokenStore {

    private record Entry(String username, Instant expiresAt) {
    }

    private final Map<String, Entry> tokens = new ConcurrentHashMap<>();

    public void save(String jti, String username, Instant expiresAt) {
        purgeExpired();
        tokens.put(jti, new Entry(username, expiresAt));
    }

    /**
     * Atomically removes the token (one-time use).
     * Returns true only if it existed and had not expired.
     */
    public boolean consume(String jti) {
        Entry entry = tokens.remove(jti);
        return entry != null && entry.expiresAt().isAfter(Instant.now());
    }

    /** Revokes every refresh token of a user (used on suspected token theft). */
    public void revokeAllForUser(String username) {
        tokens.values().removeIf(e -> e.username().equals(username));
    }

    public int size() {
        return tokens.size();
    }

    private void purgeExpired() {
        Instant now = Instant.now();
        tokens.values().removeIf(e -> !e.expiresAt().isAfter(now));
    }
}
