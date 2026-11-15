package com.example.credentialcrypto.application.service;

import com.example.credentialcrypto.application.port.in.GenerateAccessTokenUseCase;
import com.example.credentialcrypto.application.port.out.AccessTokenSigningPort;
import com.example.credentialcrypto.domain.AccessToken;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

public class AccessTokenService implements GenerateAccessTokenUseCase {
    private static final List<String> ROLES = List.of("CLIENT");

    private final AccessTokenSigningPort signingPort;
    private final Duration lifetime;

    public AccessTokenService(AccessTokenSigningPort signingPort, Duration lifetime) {
        this.signingPort = signingPort;
        this.lifetime = lifetime;
    }

    @Override
    public AccessToken generate(String subject) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(lifetime);
        String value = signingPort.sign(subject, ROLES, issuedAt, expiresAt);
        return new AccessToken(value, issuedAt, expiresAt);
    }
}
