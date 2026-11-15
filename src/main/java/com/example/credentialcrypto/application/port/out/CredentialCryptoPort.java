package com.example.credentialcrypto.application.port.out;

import com.example.credentialcrypto.domain.ConnectionCredentials;
import com.example.credentialcrypto.domain.EncryptedPayload;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;

public interface CredentialCryptoPort {
    EncryptedPayload encrypt(ConnectionCredentials credentials, EncryptionAlgorithm algorithm);

    ConnectionCredentials decrypt(EncryptedPayload payload);

    EncryptedPayload encryptServiceToken(String token, EncryptionAlgorithm algorithm);

    String decryptServiceToken(EncryptedPayload payload);

    EncryptedPayload encryptMessage(String message, EncryptionAlgorithm algorithm);

    String decryptMessage(EncryptedPayload payload);
}
