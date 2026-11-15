package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.application.service.SeededSecretResult;
import com.example.credentialcrypto.domain.SecurityAssessment;
import java.time.Instant;
import java.util.UUID;

public record SeededSecretResponse(
        UUID serial,
        String operation,
        String identityType,
        String status,
        Instant createdAt,
        int version,
        String algorithm,
        String nonce,
        String ciphertext,
        String encapsulatedKey,
        String kdfSalt,
        SecurityAssessment securityAssessment
) {
    public static SeededSecretResponse from(SeededSecretResult result) {
        var payload = result.payload();
        return new SeededSecretResponse(
                result.serial(),
                "SEEDED",
                result.identityType().name(),
                result.status().name(),
                result.createdAt(),
                payload.version(),
                payload.algorithm().name(),
                payload.nonce(),
                payload.ciphertext(),
                payload.encapsulatedKey(),
                payload.kdfSalt(),
                SecurityAssessment.forAlgorithm(payload.algorithm())
        );
    }
}
