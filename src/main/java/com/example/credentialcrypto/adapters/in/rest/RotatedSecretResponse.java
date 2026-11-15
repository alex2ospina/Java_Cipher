package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.application.service.RotatedSecretResult;
import java.time.Instant;
import java.util.UUID;

public record RotatedSecretResponse(
        UUID serial,
        String operation,
        String identityType,
        String status,
        Instant createdAt,
        String algorithm,
        String username,
        String password,
        String token
) {
    public static RotatedSecretResponse from(RotatedSecretResult result) {
        return new RotatedSecretResponse(
                result.serial(),
                "ROTATED",
                result.identityType().name(),
                result.status().name(),
                result.createdAt(),
                result.algorithm().name(),
                result.username(),
                result.password(),
                result.token()
        );
    }
}
