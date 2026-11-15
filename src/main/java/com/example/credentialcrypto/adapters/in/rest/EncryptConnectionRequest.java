package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.domain.ConnectionCredentials;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record EncryptConnectionRequest(
        @NotBlank String username,
        @NotBlank String password,
        @NotNull EncryptionAlgorithm algorithm
) {
    public ConnectionCredentials toDomain() {
        return new ConnectionCredentials(username, password);
    }
}
