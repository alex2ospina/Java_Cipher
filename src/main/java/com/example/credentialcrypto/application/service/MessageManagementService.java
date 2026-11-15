package com.example.credentialcrypto.application.service;

import com.example.credentialcrypto.application.port.in.DecryptStoredMessageUseCase;
import com.example.credentialcrypto.application.port.in.EncryptAndStoreMessageUseCase;
import com.example.credentialcrypto.application.port.out.CredentialCryptoPort;
import com.example.credentialcrypto.application.port.out.MessageArchivePort;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.EncryptionStatus;
import com.example.credentialcrypto.domain.StoredMessage;
import java.time.Instant;
import java.util.UUID;

public class MessageManagementService implements EncryptAndStoreMessageUseCase, DecryptStoredMessageUseCase {
    private final CredentialCryptoPort cryptoPort;
    private final MessageArchivePort archivePort;

    public MessageManagementService(CredentialCryptoPort cryptoPort, MessageArchivePort archivePort) {
        this.cryptoPort = cryptoPort;
        this.archivePort = archivePort;
    }

    @Override
    public StoredMessage encryptAndStore(String message, EncryptionAlgorithm algorithm) {
        StoredMessage storedMessage = new StoredMessage(
                UUID.randomUUID(),
                EncryptionStatus.ENCRYPTED,
                cryptoPort.encryptMessage(message, algorithm),
                Instant.now()
        );
        archivePort.save(storedMessage);
        return storedMessage;
    }

    @Override
    public StoredMessageDecryptionResult decryptStoredMessage(UUID serial) {
        StoredMessage storedMessage = archivePort.findBySerial(serial)
                .orElseThrow(() -> new ConnectionNotFoundException(serial));
        return new StoredMessageDecryptionResult(
                storedMessage.serial(),
                storedMessage.status(),
                cryptoPort.decryptMessage(storedMessage.payload())
        );
    }
}
