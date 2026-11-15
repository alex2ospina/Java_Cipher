package com.example.credentialcrypto.application.port.in;

import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.StoredServiceToken;

public interface EncryptAndStoreServiceTokenUseCase {
    StoredServiceToken encryptAndStore(String token, EncryptionAlgorithm algorithm);
}
