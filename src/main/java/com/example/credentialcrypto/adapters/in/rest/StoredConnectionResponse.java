package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.domain.EncryptedPayload;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.EncryptionStatus;
import com.example.credentialcrypto.domain.SecurityAssessment;
import com.example.credentialcrypto.domain.StoredConnection;
import java.time.Instant;
import java.util.UUID;

public record StoredConnectionResponse(
        UUID serial,
        EncryptionStatus status,
        Instant createdAt,
        int version,
        EncryptionAlgorithm algorithm,
        String nonce,
        String ciphertext,
        String encapsulatedKey,
        String kdfSalt,
        SecurityAssessment securityAssessment
) {
    public static StoredConnectionResponse from(StoredConnection connection) {
        EncryptedPayload payload = connection.payload();
        return new StoredConnectionResponse(
                connection.serial(),
                connection.status(),
                connection.createdAt(),
                payload.version(),
                payload.algorithm(),
                payload.nonce(),
                payload.ciphertext(),
                payload.encapsulatedKey(),
                payload.kdfSalt(),
                SecurityAssessment.forAlgorithm(payload.algorithm())
        );
    }
}
