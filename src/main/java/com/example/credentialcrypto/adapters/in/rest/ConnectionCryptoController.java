package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.application.port.in.DecryptConnectionUseCase;
import com.example.credentialcrypto.application.port.in.DecryptStoredServiceTokenUseCase;
import com.example.credentialcrypto.application.port.in.DecryptStoredConnectionUseCase;
import com.example.credentialcrypto.application.port.in.EncryptAndStoreConnectionUseCase;
import com.example.credentialcrypto.application.port.in.EncryptAndStoreServiceTokenUseCase;
import com.example.credentialcrypto.application.port.in.EncryptConnectionUseCase;
import com.example.credentialcrypto.application.port.in.RotateSecretUseCase;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/connections")
public class ConnectionCryptoController {
    private final EncryptConnectionUseCase encryptUseCase;
    private final DecryptConnectionUseCase decryptUseCase;
    private final EncryptAndStoreConnectionUseCase encryptAndStoreUseCase;
    private final DecryptStoredConnectionUseCase decryptStoredUseCase;
    private final EncryptAndStoreServiceTokenUseCase encryptAndStoreServiceTokenUseCase;
    private final DecryptStoredServiceTokenUseCase decryptStoredServiceTokenUseCase;
    private final RotateSecretUseCase rotateSecretUseCase;

    public ConnectionCryptoController(
            EncryptConnectionUseCase encryptUseCase,
            DecryptConnectionUseCase decryptUseCase,
            EncryptAndStoreConnectionUseCase encryptAndStoreUseCase,
            DecryptStoredConnectionUseCase decryptStoredUseCase,
            EncryptAndStoreServiceTokenUseCase encryptAndStoreServiceTokenUseCase,
            DecryptStoredServiceTokenUseCase decryptStoredServiceTokenUseCase,
            RotateSecretUseCase rotateSecretUseCase
    ) {
        this.encryptUseCase = encryptUseCase;
        this.decryptUseCase = decryptUseCase;
        this.encryptAndStoreUseCase = encryptAndStoreUseCase;
        this.decryptStoredUseCase = decryptStoredUseCase;
        this.encryptAndStoreServiceTokenUseCase = encryptAndStoreServiceTokenUseCase;
        this.decryptStoredServiceTokenUseCase = decryptStoredServiceTokenUseCase;
        this.rotateSecretUseCase = rotateSecretUseCase;
    }

    @PostMapping("/service-tokens")
    @ResponseStatus(HttpStatus.CREATED)
    public StoredServiceTokenResponse encryptAndStoreServiceToken(
            @Valid @RequestBody EncryptServiceTokenRequest request
    ) {
        return StoredServiceTokenResponse.from(
                encryptAndStoreServiceTokenUseCase.encryptAndStore(request.token(), request.algorithm())
        );
    }

    @PostMapping("/service-tokens/{serial}/decrypt")
    @ResponseStatus(HttpStatus.OK)
    public DecryptedServiceTokenResponse decryptStoredServiceToken(@PathVariable UUID serial) {
        return DecryptedServiceTokenResponse.from(
                decryptStoredServiceTokenUseCase.decryptStoredServiceToken(serial)
        );
    }

    @PostMapping("/service-tokens/{serial}/rotate")
    @ResponseStatus(HttpStatus.CREATED)
    public RotatedSecretResponse rotateServiceToken(@PathVariable UUID serial) {
        return RotatedSecretResponse.from(rotateSecretUseCase.rotate(serial));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public StoredConnectionResponse encryptAndStore(@Valid @RequestBody EncryptConnectionRequest request) {
        return StoredConnectionResponse.from(
                encryptAndStoreUseCase.encryptAndStore(request.toDomain(), request.algorithm())
        );
    }

    @PostMapping("/{serial}/decrypt")
    @ResponseStatus(HttpStatus.OK)
    public StoredDecryptionResponse decryptStored(@PathVariable UUID serial) {
        return StoredDecryptionResponse.from(decryptStoredUseCase.decryptStoredConnection(serial));
    }

    @PostMapping("/{serial}/rotate")
    @ResponseStatus(HttpStatus.CREATED)
    public RotatedSecretResponse rotateConnection(@PathVariable UUID serial) {
        return RotatedSecretResponse.from(rotateSecretUseCase.rotate(serial));
    }

    @PostMapping("/encrypt")
    @ResponseStatus(HttpStatus.OK)
    public EncryptedConnectionResponse encrypt(@Valid @RequestBody EncryptConnectionRequest request) {
        return EncryptedConnectionResponse.from(
                encryptUseCase.encrypt(request.toDomain(), request.algorithm())
        );
    }

    @PostMapping("/decrypt")
    @ResponseStatus(HttpStatus.OK)
    public DecryptConnectionResponse decrypt(@Valid @RequestBody DecryptConnectionRequest request) {
        return DecryptConnectionResponse.from(decryptUseCase.decrypt(request.toDomain()));
    }
}
