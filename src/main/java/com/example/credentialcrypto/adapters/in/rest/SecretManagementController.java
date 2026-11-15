package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.application.port.in.RotateSecretUseCase;
import com.example.credentialcrypto.application.port.in.SeedSecretUseCase;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretManagementController {
    private final SeedSecretUseCase seedSecretUseCase;
    private final RotateSecretUseCase rotateSecretUseCase;

    public SecretManagementController(
            SeedSecretUseCase seedSecretUseCase,
            RotateSecretUseCase rotateSecretUseCase
    ) {
        this.seedSecretUseCase = seedSecretUseCase;
        this.rotateSecretUseCase = rotateSecretUseCase;
    }

    @PostMapping("/seed")
    @ResponseStatus(HttpStatus.CREATED)
    public SeededSecretResponse seed(@Valid @RequestBody SeedSecretRequest request) {
        return SeededSecretResponse.from(seedSecretUseCase.seed(request.toCommand()));
    }

    @PostMapping("/rotate")
    @ResponseStatus(HttpStatus.CREATED)
    public RotatedSecretResponse rotate(@Valid @RequestBody RotateSecretRequest request) {
        return RotatedSecretResponse.from(rotateSecretUseCase.rotate(request.serial()));
    }
}
