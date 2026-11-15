package com.example.credentialcrypto.application.port.in;

import com.example.credentialcrypto.domain.ConnectionCredentials;
import com.example.credentialcrypto.domain.EncryptedPayload;

public interface DecryptConnectionUseCase {
    ConnectionCredentials decrypt(EncryptedPayload payload);
}
