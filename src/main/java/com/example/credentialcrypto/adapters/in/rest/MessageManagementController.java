package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.application.port.in.DecryptStoredMessageUseCase;
import com.example.credentialcrypto.application.port.in.EncryptAndStoreMessageUseCase;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/messages")
public class MessageManagementController {
    private final EncryptAndStoreMessageUseCase encryptAndStoreUseCase;
    private final DecryptStoredMessageUseCase decryptStoredUseCase;

    public MessageManagementController(
            EncryptAndStoreMessageUseCase encryptAndStoreUseCase,
            DecryptStoredMessageUseCase decryptStoredUseCase
    ) {
        this.encryptAndStoreUseCase = encryptAndStoreUseCase;
        this.decryptStoredUseCase = decryptStoredUseCase;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public StoredMessageResponse encryptAndStore(@Valid @RequestBody EncryptMessageRequest request) {
        return StoredMessageResponse.from(
                encryptAndStoreUseCase.encryptAndStore(request.message(), request.algorithm())
        );
    }

    @PostMapping("/{serial}/decrypt")
    public DecryptedMessageResponse decryptStored(@PathVariable UUID serial) {
        return DecryptedMessageResponse.from(decryptStoredUseCase.decryptStoredMessage(serial));
    }
}
