package com.example.credentialcrypto.application.port.in;

import com.example.credentialcrypto.application.service.SeedSecretCommand;
import com.example.credentialcrypto.application.service.SeededSecretResult;

public interface SeedSecretUseCase {
    SeededSecretResult seed(SeedSecretCommand command);
}
