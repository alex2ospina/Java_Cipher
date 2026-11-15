package com.example.credentialcrypto.application.port.in;

import com.example.credentialcrypto.application.service.StoredDecryptionResult;
import java.util.UUID;

public interface DecryptStoredConnectionUseCase {
    StoredDecryptionResult decryptStoredConnection(UUID serial);
}
