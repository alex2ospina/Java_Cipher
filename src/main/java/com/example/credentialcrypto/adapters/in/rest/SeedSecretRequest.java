package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.application.service.SeedSecretCommand;
import com.example.credentialcrypto.domain.ConnectionCredentials;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.SecretIdentityType;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;

public record SeedSecretRequest(
        @NotNull SecretIdentityType identityType,
        String username,
        String password,
        String token,
        @NotNull EncryptionAlgorithm algorithm
) {
    @AssertTrue(message = "Proporcione usuario y contraseña o un token, según identityType.")
    public boolean isIdentityDataValid() {
        if (identityType == null) {
            return true;
        }
        return switch (identityType) {
            case CONNECTION_CREDENTIALS -> notBlank(username) && notBlank(password) && token == null;
            case SERVICE_TOKEN -> notBlank(token) && username == null && password == null;
        };
    }

    public SeedSecretCommand toCommand() {
        ConnectionCredentials credentials = identityType == SecretIdentityType.CONNECTION_CREDENTIALS
                ? new ConnectionCredentials(username, password)
                : null;
        String serviceToken = identityType == SecretIdentityType.SERVICE_TOKEN ? token : null;
        return new SeedSecretCommand(identityType, credentials, serviceToken, algorithm);
    }

    private boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }
}
