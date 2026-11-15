package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record EncryptMessageRequest(
        @NotBlank @Size(max = 1_000_000) String message,
        @NotNull EncryptionAlgorithm algorithm
) {
}
