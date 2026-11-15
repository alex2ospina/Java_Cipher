package com.example.credentialcrypto.domain;

import java.time.Instant;
import java.util.UUID;

public record StoredMessage(
        UUID serial,
        EncryptionStatus status,
        EncryptedPayload payload,
        Instant createdAt
) {
}
