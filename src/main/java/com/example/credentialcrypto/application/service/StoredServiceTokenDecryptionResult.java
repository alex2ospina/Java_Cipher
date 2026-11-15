package com.example.credentialcrypto.application.service;

import com.example.credentialcrypto.domain.EncryptionStatus;
import java.util.UUID;

public record StoredServiceTokenDecryptionResult(UUID serial, EncryptionStatus status, String token) {
}
