package com.example.jwtdemo.security;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TokenCacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    // Prefix to avoid key collisions
    private static final String TOKEN_PREFIX = "jwt:token:";
    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";

    public TokenCacheService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // Store a valid token (e.g. after login)
    public void storeToken(String token, long expirationSeconds) {
        String key = TOKEN_PREFIX + token;
        redisTemplate.opsForValue().set(key, "valid", expirationSeconds, TimeUnit.SECONDS);
    }

    // Check if token is still valid / exists
    public boolean isTokenValid(String token) {
        return redisTemplate.hasKey(TOKEN_PREFIX + token);
    }

    // Blacklist a token (on logout)
    public void blacklistToken(String token, long remainingSeconds) {
        if (remainingSeconds > 0) {
            redisTemplate.opsForValue().set(
                    BLACKLIST_PREFIX + token,
                    "blacklisted",
                    remainingSeconds,
                    TimeUnit.SECONDS
            );
        }
    }

    public boolean isTokenBlacklisted(String token) {
        return redisTemplate.hasKey(BLACKLIST_PREFIX + token);
    }

    // Optional: remove token completely
    public void removeToken(String token) {
        redisTemplate.delete(TOKEN_PREFIX + token);
        redisTemplate.delete(BLACKLIST_PREFIX + token);
    }
}
