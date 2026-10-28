package com.example.jwtdemo.service;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class ExternalApiService {

    private static final Logger log = LoggerFactory.getLogger(ExternalApiService.class);

    private final RestTemplate restTemplate = new RestTemplate();

    private static final String USER_SERVICE_URL = "http://localhost:8081";

    /**
     * Order of annotations matters
     */
    @CircuitBreaker(name = "externalService", fallbackMethod = "fallback")
    @Retry(name = "externalService")
    public String callExternalService(String userId) {
        log.info("Calling external service for id={}", userId);

        String url = USER_SERVICE_URL + "/api/users";

        return restTemplate.getForObject(
                url,
                String.class
        );
    }

    // Fallback method (must have same return type + extra Throwable parameter)
    private String fallback(String id, Throwable t) {
        log.warn("CircuitBreaker/Retry fallback triggered for id={}. Reason: {}", id, t.toString());
        return "Service temporarily unavailable. Please try again later.";
    }
}
