package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.domain.EncryptedPayload;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@JsonIgnoreProperties(ignoreUnknown = true)
public record DecryptConnectionRequest(
        int version,
        @NotNull EncryptionAlgorithm algorithm,
        @NotBlank String nonce,
        @NotBlank String ciphertext,
        String encapsulatedKey,
        String kdfSalt
) {
    public EncryptedPayload toDomain() {
        return new EncryptedPayload(version, algorithm, nonce, ciphertext, encapsulatedKey, kdfSalt);
    }
}
