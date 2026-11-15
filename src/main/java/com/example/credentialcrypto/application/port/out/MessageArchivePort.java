package com.example.credentialcrypto.application.port.out;

import com.example.credentialcrypto.domain.StoredMessage;
import java.util.Optional;
import java.util.UUID;

public interface MessageArchivePort {
    void save(StoredMessage message);

    Optional<StoredMessage> findBySerial(UUID serial);
}
