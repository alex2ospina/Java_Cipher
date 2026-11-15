package com.example.credentialcrypto.application.service;

import com.example.credentialcrypto.domain.ConnectionCredentials;
import com.example.credentialcrypto.domain.EncryptionStatus;
import java.util.UUID;

public record StoredDecryptionResult(UUID serial, EncryptionStatus status, ConnectionCredentials credentials) {
}
