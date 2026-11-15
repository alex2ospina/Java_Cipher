package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.application.service.EncryptionResult;
import com.example.credentialcrypto.domain.EncryptedPayload;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.SecurityAssessment;

public record EncryptedConnectionResponse(
        int version,
        EncryptionAlgorithm algorithm,
        String nonce,
        String ciphertext,
        String encapsulatedKey,
        String kdfSalt,
        SecurityAssessment securityAssessment
) {
    public static EncryptedConnectionResponse from(EncryptionResult result) {
        EncryptedPayload payload = result.payload();
        return new EncryptedConnectionResponse(
                payload.version(),
                payload.algorithm(),
                payload.nonce(),
                payload.ciphertext(),
                payload.encapsulatedKey(),
                payload.kdfSalt(),
                result.securityAssessment()
        );
    }
}
