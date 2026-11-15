package com.example.credentialcrypto.application.service;

import com.example.credentialcrypto.domain.ConnectionCredentials;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.SecretIdentityType;

public record SeedSecretCommand(
        SecretIdentityType identityType,
        ConnectionCredentials credentials,
        String token,
        EncryptionAlgorithm algorithm
) {
}
