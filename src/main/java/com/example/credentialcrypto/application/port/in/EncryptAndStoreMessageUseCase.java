package com.example.credentialcrypto.application.port.in;

import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.StoredMessage;

public interface EncryptAndStoreMessageUseCase {
    StoredMessage encryptAndStore(String message, EncryptionAlgorithm algorithm);
}
