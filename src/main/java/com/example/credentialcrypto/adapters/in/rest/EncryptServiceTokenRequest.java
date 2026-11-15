package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record EncryptServiceTokenRequest(
        @NotBlank String token,
        @NotNull EncryptionAlgorithm algorithm
) {
}
