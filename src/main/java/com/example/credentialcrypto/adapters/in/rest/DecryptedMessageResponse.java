package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.application.service.StoredMessageDecryptionResult;
import java.util.UUID;

public record DecryptedMessageResponse(UUID serial, String status, String message) {
    public static DecryptedMessageResponse from(StoredMessageDecryptionResult result) {
        return new DecryptedMessageResponse(
                result.serial(),
                result.status().name(),
                result.message()
        );
    }
}
