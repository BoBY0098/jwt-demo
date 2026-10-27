# JWT + Spring Security demo (access + refresh tokens)

Run: `mvn spring-boot:run` (Java 17+). Test: `mvn test`.

```bash
# 1. login -> accessToken (15 min) + refreshToken (7 days)
curl -s -X POST localhost:8084/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"user","password":"password"}'

# 2. call a protected endpoint with the ACCESS token
curl -s localhost:8084/api/me -H "Authorization: Bearer <accessToken>"

# 3. access token expired (401 "Access token expired")? get a new pair with the REFRESH token
curl -s -X POST localhost:8084/api/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refreshToken>"}'

# 4. logout = revoke the refresh token
curl -s -X POST localhost:8084/api/auth/logout -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refreshToken>"}'

# admin only (login as admin / admin123, otherwise 403)
curl -s localhost:8084/api/admin/ping -H "Authorization: Bearer <accessToken>"
```

## Refresh token design
- Both tokens are signed JWTs, told apart by the `type` claim (`access` / `refresh`).
  A refresh token is rejected on API calls and an access token is rejected on `/refresh`.
- **Rotation:** every `/refresh` call returns a NEW access AND refresh token; the old
  refresh token is deleted (one-time use).
- **Reuse detection:** if an already-used refresh token shows up again, all refresh tokens
  of that user are revoked, so a stolen token cannot silently live on.
- Valid refresh token ids (`jti`) are kept in `RefreshTokenStore`. It is in-memory for the
  demo; use a DB or Redis in production (tokens are lost on restart otherwise).
- The refresh token carries no roles; roles are reloaded from the `UserDetailsService`
  on every refresh, so role changes and disabled accounts take effect.

Settings (`application.yml`): `jwt.access-token-expiration-ms`, `jwt.refresh-token-expiration-ms`.
