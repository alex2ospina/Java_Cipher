package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.application.service.StoredDecryptionResult;
import com.example.credentialcrypto.domain.EncryptionStatus;
import java.util.UUID;

public record StoredDecryptionResponse(
        UUID serial,
        EncryptionStatus status,
        String username,
        String password
) {
    public static StoredDecryptionResponse from(StoredDecryptionResult result) {
        return new StoredDecryptionResponse(
                result.serial(),
                result.status(),
                result.credentials().username(),
                result.credentials().password()
        );
    }
}
