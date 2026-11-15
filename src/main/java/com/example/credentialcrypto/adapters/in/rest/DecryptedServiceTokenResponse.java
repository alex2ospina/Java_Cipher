package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.application.service.StoredServiceTokenDecryptionResult;
import com.example.credentialcrypto.domain.EncryptionStatus;
import java.util.UUID;

public record DecryptedServiceTokenResponse(
        UUID serial,
        EncryptionStatus status,
        String token
) {
    public static DecryptedServiceTokenResponse from(StoredServiceTokenDecryptionResult result) {
        return new DecryptedServiceTokenResponse(result.serial(), result.status(), result.token());
    }
}
