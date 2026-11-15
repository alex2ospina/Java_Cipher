package com.example.credentialcrypto.application.service;

import com.example.credentialcrypto.domain.EncryptedPayload;
import com.example.credentialcrypto.domain.EncryptionStatus;
import com.example.credentialcrypto.domain.SecretIdentityType;
import java.time.Instant;
import java.util.UUID;

public record SeededSecretResult(
        UUID serial,
        SecretIdentityType identityType,
        EncryptionStatus status,
        Instant createdAt,
        EncryptedPayload payload
) {
}
