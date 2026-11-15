package com.example.credentialcrypto.application.port.in;

import com.example.credentialcrypto.application.service.StoredMessageDecryptionResult;
import java.util.UUID;

public interface DecryptStoredMessageUseCase {
    StoredMessageDecryptionResult decryptStoredMessage(UUID serial);
}
