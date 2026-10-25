package com.example.jwtdemo.web;

import com.example.jwtdemo.security.JwtService;
import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@Tag(name = "API", description = "Account info API's")
public class ApiController {

    private final JwtService jwtService;

    public ApiController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /** Shows the claims that were read from the validated token. */
    @GetMapping("/me")
    public Map<String, Object> me(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization) {
        Claims c = jwtService.parseAccessToken(authorization.substring("Bearer ".length()));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sub", c.getSubject());
        out.put("roles", c.get(JwtService.ROLES_CLAIM));
        out.put("type", c.get(JwtService.TYPE_CLAIM));
        out.put("iss", c.getIssuer());
        out.put("jti", c.getId());
        out.put("iat", c.getIssuedAt());
        out.put("exp", c.getExpiration());
        return out;
    }

    @GetMapping("/admin/ping")
    public Map<String, String> adminPing() {
        return Map.of("message", "pong from admin area");
    }
}
