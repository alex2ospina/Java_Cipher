package com.example.credentialcrypto.application.port.out;

import com.example.credentialcrypto.domain.StoredConnection;
import java.util.Optional;
import java.util.UUID;

public interface ConnectionArchivePort {
    void save(StoredConnection connection);

    Optional<StoredConnection> findBySerial(UUID serial);

    boolean replace(UUID oldSerial, StoredConnection replacement);
}
