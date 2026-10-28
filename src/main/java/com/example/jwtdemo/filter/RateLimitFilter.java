package com.example.jwtdemo.filter;

import com.example.jwtdemo.config.RateLimitProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)  // After CorrelationIdFilter
public class RateLimitFilter extends OncePerRequestFilter {

    private final StringRedisTemplate redisTemplate;
    private final RateLimitProperties properties;
    private final ObjectMapper objectMapper;

    public RateLimitFilter(StringRedisTemplate redisTemplate, RateLimitProperties properties, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // Skip if it's disable
        if (!properties.isEnabled()) {
            filterChain.doFilter(request, response);
        }

        // Skip swagger & actuator
        String path = request.getRequestURI();
        if (path.startsWith("/swagger-ui") || path.startsWith("/v3/api-docs") || path.startsWith("/webjars")) {
            filterChain.doFilter(request, response);
        }

        String key = buildKey(request);

        Long currentCount = redisTemplate.opsForValue().increment(key);
        if (currentCount != null && currentCount == 1) {
            // Setting expire for First Request
            redisTemplate.expire(key, properties.getWindowSeconds(), TimeUnit.SECONDS);
        }

        // Returining Remain info in header
        long remaining = Math.max(0, properties.getMaxRequests() - (currentCount == null ? 0 : currentCount));
        response.setHeader("X-RateLimit-Limit", String.valueOf(properties.getMaxRequests()));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(remaining));
        response.setHeader("X-RateLimit-Window", properties.getWindowSeconds() + "s");

        if (currentCount != null && currentCount > properties.getMaxRequests()) {
            writeTooManyRequests(response, key);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private String buildKey(HttpServletRequest request) {
        // Prefer ID (authenticated user) first
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !auth.getPrincipal().equals("anonymousUser")) {
            return "rate-limit:user:" +  auth.getName();
        }
        String ip = extractClientIp(request);
        return "rate-limit:ip:" + ip;
    }

    private String extractClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            // Take the first IP in the chain
            return xff.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr();
    }

    private void writeTooManyRequests(HttpServletResponse response, String key) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("429", 429);
        body.put("error", "Too Many Requests");
        body.put("message", "Rate limit exceeded. Max "
                + properties.getMaxRequests() + " requests per "
                + properties.getWindowSeconds() + " seconds.");
        body.put("path", key);

        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
