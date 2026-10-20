package com.example.jwtdemo.web;

public record TokenResponse(String accessToken,
                            String refreshToken,
                            String tokenType,
                            long expiresIn,
                            long refreshExpiresIn) {
}
