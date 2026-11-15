package com.example.credentialcrypto.application.port.out;

import com.example.credentialcrypto.domain.StoredServiceToken;
import java.util.Optional;
import java.util.UUID;

public interface ServiceTokenArchivePort {
    void save(StoredServiceToken token);

    Optional<StoredServiceToken> findBySerial(UUID serial);

    boolean replace(UUID oldSerial, StoredServiceToken replacement);
}
