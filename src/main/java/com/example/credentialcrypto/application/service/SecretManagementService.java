package com.example.credentialcrypto.application.service;

import com.example.credentialcrypto.application.port.in.DecryptConnectionUseCase;
import com.example.credentialcrypto.application.port.in.DecryptStoredServiceTokenUseCase;
import com.example.credentialcrypto.application.port.in.DecryptStoredConnectionUseCase;
import com.example.credentialcrypto.application.port.in.EncryptAndStoreConnectionUseCase;
import com.example.credentialcrypto.application.port.in.EncryptAndStoreServiceTokenUseCase;
import com.example.credentialcrypto.application.port.in.EncryptConnectionUseCase;
import com.example.credentialcrypto.application.port.in.RotateSecretUseCase;
import com.example.credentialcrypto.application.port.in.SeedSecretUseCase;
import com.example.credentialcrypto.application.port.out.ConnectionArchivePort;
import com.example.credentialcrypto.application.port.out.CredentialCryptoPort;
import com.example.credentialcrypto.application.port.out.ServiceTokenArchivePort;
import com.example.credentialcrypto.application.port.out.ServiceTokenIssuerPort;
import com.example.credentialcrypto.domain.ConnectionCredentials;
import com.example.credentialcrypto.domain.EncryptedPayload;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.EncryptionStatus;
import com.example.credentialcrypto.domain.SecretIdentityType;
import com.example.credentialcrypto.domain.SecurityAssessment;
import com.example.credentialcrypto.domain.StoredConnection;
import com.example.credentialcrypto.domain.StoredServiceToken;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

public class SecretManagementService implements
        EncryptConnectionUseCase,
        DecryptConnectionUseCase,
        EncryptAndStoreConnectionUseCase,
        DecryptStoredConnectionUseCase,
        EncryptAndStoreServiceTokenUseCase,
        DecryptStoredServiceTokenUseCase,
        SeedSecretUseCase,
        RotateSecretUseCase {
    private static final EncryptionAlgorithm ROTATION_ALGORITHM =
            EncryptionAlgorithm.ML_KEM_768_AES_256_GCM;
    private static final String PASSWORD_CHARACTERS =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+";

    private final CredentialCryptoPort cryptoPort;
    private final ConnectionArchivePort archivePort;
    private final ServiceTokenArchivePort serviceTokenArchivePort;
    private final ServiceTokenIssuerPort serviceTokenIssuerPort;
    private final SecureRandom secureRandom = new SecureRandom();

    public SecretManagementService(
            CredentialCryptoPort cryptoPort,
            ConnectionArchivePort archivePort,
            ServiceTokenArchivePort serviceTokenArchivePort,
            ServiceTokenIssuerPort serviceTokenIssuerPort
    ) {
        this.cryptoPort = cryptoPort;
        this.archivePort = archivePort;
        this.serviceTokenArchivePort = serviceTokenArchivePort;
        this.serviceTokenIssuerPort = serviceTokenIssuerPort;
    }

    @Override
    public EncryptionResult encrypt(ConnectionCredentials credentials, EncryptionAlgorithm algorithm) {
        EncryptedPayload payload = cryptoPort.encrypt(credentials, algorithm);
        return new EncryptionResult(payload, SecurityAssessment.forAlgorithm(algorithm));
    }

    @Override
    public ConnectionCredentials decrypt(EncryptedPayload payload) {
        return cryptoPort.decrypt(payload);
    }

    @Override
    public StoredConnection encryptAndStore(ConnectionCredentials credentials, EncryptionAlgorithm algorithm) {
        EncryptedPayload payload = cryptoPort.encrypt(credentials, algorithm);
        StoredConnection connection = new StoredConnection(
                UUID.randomUUID(),
                EncryptionStatus.ENCRYPTED,
                payload,
                Instant.now()
        );
        archivePort.save(connection);
        return connection;
    }

    @Override
    public StoredDecryptionResult decryptStoredConnection(UUID serial) {
        StoredConnection connection = archivePort.findBySerial(serial)
                .orElseThrow(() -> new ConnectionNotFoundException(serial));
        return new StoredDecryptionResult(
                connection.serial(),
                connection.status(),
                cryptoPort.decrypt(connection.payload())
        );
    }

    @Override
    public StoredServiceToken encryptAndStore(String token, EncryptionAlgorithm algorithm) {
        StoredServiceToken storedToken = new StoredServiceToken(
                UUID.randomUUID(),
                EncryptionStatus.ENCRYPTED,
                cryptoPort.encryptServiceToken(token, algorithm),
                Instant.now()
        );
        serviceTokenArchivePort.save(storedToken);
        return storedToken;
    }

    @Override
    public StoredServiceTokenDecryptionResult decryptStoredServiceToken(UUID serial) {
        StoredServiceToken storedToken = serviceTokenArchivePort.findBySerial(serial)
                .orElseThrow(() -> new ConnectionNotFoundException(serial));
        return new StoredServiceTokenDecryptionResult(
                storedToken.serial(),
                storedToken.status(),
                cryptoPort.decryptServiceToken(storedToken.payload())
        );
    }

    @Override
    public SeededSecretResult seed(SeedSecretCommand command) {
        return switch (command.identityType()) {
            case CONNECTION_CREDENTIALS -> {
                StoredConnection stored = encryptAndStore(command.credentials(), command.algorithm());
                yield new SeededSecretResult(
                        stored.serial(), command.identityType(), stored.status(), stored.createdAt(), stored.payload());
            }
            case SERVICE_TOKEN -> {
                StoredServiceToken stored = encryptAndStore(command.token(), command.algorithm());
                yield new SeededSecretResult(
                        stored.serial(), command.identityType(), stored.status(), stored.createdAt(), stored.payload());
            }
        };
    }

    @Override
    public RotatedSecretResult rotate(UUID serial) {
        var storedConnection = archivePort.findBySerial(serial);
        if (storedConnection.isPresent()) {
            ConnectionCredentials current = cryptoPort.decrypt(storedConnection.get().payload());
            ConnectionCredentials replacementCredentials =
                    new ConnectionCredentials(current.username(), generatePassword());
            StoredConnection replacement = new StoredConnection(
                    UUID.randomUUID(),
                    EncryptionStatus.ENCRYPTED,
                    cryptoPort.encrypt(replacementCredentials, ROTATION_ALGORITHM),
                    Instant.now()
            );
            if (!archivePort.replace(serial, replacement)) {
                throw new ConnectionNotFoundException(serial);
            }
            return new RotatedSecretResult(
                    replacement.serial(),
                    SecretIdentityType.CONNECTION_CREDENTIALS,
                    replacement.status(),
                    replacement.createdAt(),
                    replacement.payload().algorithm(),
                    replacementCredentials.username(),
                    replacementCredentials.password(),
                    null
            );
        }

        StoredServiceToken storedToken = serviceTokenArchivePort.findBySerial(serial)
                .orElseThrow(() -> new ConnectionNotFoundException(serial));
        String currentToken = cryptoPort.decryptServiceToken(storedToken.payload());
        String replacementToken = serviceTokenIssuerPort.rotate(currentToken);
        if (replacementToken == null || replacementToken.isBlank()) {
            throw new ServiceTokenIssuerUnavailableException("El emisor devolvió un token vacío.");
        }
        StoredServiceToken replacement = new StoredServiceToken(
                UUID.randomUUID(),
                EncryptionStatus.ENCRYPTED,
                cryptoPort.encryptServiceToken(replacementToken, ROTATION_ALGORITHM),
                Instant.now()
        );
        if (!serviceTokenArchivePort.replace(serial, replacement)) {
            throw new ConnectionNotFoundException(serial);
        }
        return new RotatedSecretResult(
                replacement.serial(),
                SecretIdentityType.SERVICE_TOKEN,
                replacement.status(),
                replacement.createdAt(),
                replacement.payload().algorithm(),
                null,
                null,
                replacementToken
        );
    }

    private String generatePassword() {
        char[] password = new char[32];
        password[0] = randomFrom("ABCDEFGHJKLMNPQRSTUVWXYZ");
        password[1] = randomFrom("abcdefghijkmnopqrstuvwxyz");
        password[2] = randomFrom("23456789");
        password[3] = randomFrom("!@#$%^&*()-_=+");
        for (int index = 4; index < password.length; index++) {
            password[index] = randomFrom(PASSWORD_CHARACTERS);
        }
        for (int index = password.length - 1; index > 0; index--) {
            int swapIndex = secureRandom.nextInt(index + 1);
            char current = password[index];
            password[index] = password[swapIndex];
            password[swapIndex] = current;
        }
        return new String(password);
    }

    private char randomFrom(String characters) {
        return characters.charAt(secureRandom.nextInt(characters.length()));
    }
}
