package com.example.credentialcrypto.application.port.in;

import com.example.credentialcrypto.application.service.EncryptionResult;
import com.example.credentialcrypto.domain.ConnectionCredentials;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;

public interface EncryptConnectionUseCase {
    EncryptionResult encrypt(ConnectionCredentials credentials, EncryptionAlgorithm algorithm);
}
