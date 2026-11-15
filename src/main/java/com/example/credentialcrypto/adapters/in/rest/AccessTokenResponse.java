package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.domain.AccessToken;
import java.time.Duration;
import java.time.Instant;

public record AccessTokenResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        Instant issuedAt,
        Instant expiresAt
) {
    public static AccessTokenResponse from(AccessToken token) {
        return new AccessTokenResponse(
                token.value(),
                "Bearer",
                Duration.between(token.issuedAt(), token.expiresAt()).toSeconds(),
                token.issuedAt(),
                token.expiresAt()
        );
    }
}
