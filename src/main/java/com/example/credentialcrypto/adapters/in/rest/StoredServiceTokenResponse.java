package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.domain.EncryptionStatus;
import com.example.credentialcrypto.domain.SecurityAssessment;
import com.example.credentialcrypto.domain.StoredServiceToken;
import java.time.Instant;
import java.util.UUID;

public record StoredServiceTokenResponse(
        UUID serial,
        EncryptionStatus status,
        Instant createdAt,
        int version,
        String algorithm,
        String nonce,
        String ciphertext,
        String encapsulatedKey,
        String kdfSalt,
        SecurityAssessment securityAssessment
) {
    public static StoredServiceTokenResponse from(StoredServiceToken token) {
        var payload = token.payload();
        return new StoredServiceTokenResponse(
                token.serial(),
                token.status(),
                token.createdAt(),
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
