package com.example.jwtdemo.security;

import java.time.Instant;

/** A freshly generated token together with the metadata we need to track it. */
public record IssuedToken(String token, String jti, Instant expiresAt) {
}
