package com.example.credentialcrypto.application.port.in;

import com.example.credentialcrypto.domain.ConnectionCredentials;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.StoredConnection;

public interface EncryptAndStoreConnectionUseCase {
    StoredConnection encryptAndStore(ConnectionCredentials credentials, EncryptionAlgorithm algorithm);
}
