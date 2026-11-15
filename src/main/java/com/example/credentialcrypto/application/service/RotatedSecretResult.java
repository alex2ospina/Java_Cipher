package com.example.credentialcrypto.application.service;

import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.EncryptionStatus;
import com.example.credentialcrypto.domain.SecretIdentityType;
import java.time.Instant;
import java.util.UUID;

public record RotatedSecretResult(
        UUID serial,
        SecretIdentityType identityType,
        EncryptionStatus status,
        Instant createdAt,
        EncryptionAlgorithm algorithm,
        String username,
        String password,
        String token
) {
}
