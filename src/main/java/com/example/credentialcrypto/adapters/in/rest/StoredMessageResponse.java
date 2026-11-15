package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.domain.SecurityAssessment;
import com.example.credentialcrypto.domain.StoredMessage;
import java.time.Instant;
import java.util.UUID;

public record StoredMessageResponse(
        UUID serial,
        String operation,
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
    public static StoredMessageResponse from(StoredMessage storedMessage) {
        var payload = storedMessage.payload();
        return new StoredMessageResponse(
                storedMessage.serial(),
                "ENCRYPTED",
                storedMessage.status().name(),
                storedMessage.createdAt(),
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
