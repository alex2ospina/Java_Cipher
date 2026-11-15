package com.example.credentialcrypto.adapters.in.rest;

import jakarta.validation.constraints.NotBlank;

public record GenerateAccessTokenRequest(
        @NotBlank String username,
        @NotBlank String password
) {
}
