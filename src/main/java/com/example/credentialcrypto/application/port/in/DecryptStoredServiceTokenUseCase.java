package com.example.credentialcrypto.application.port.in;

import com.example.credentialcrypto.application.service.StoredServiceTokenDecryptionResult;
import java.util.UUID;

public interface DecryptStoredServiceTokenUseCase {
    StoredServiceTokenDecryptionResult decryptStoredServiceToken(UUID serial);
}
