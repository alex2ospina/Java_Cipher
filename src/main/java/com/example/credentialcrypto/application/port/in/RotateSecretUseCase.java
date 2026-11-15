package com.example.credentialcrypto.application.port.in;

import com.example.credentialcrypto.application.service.RotatedSecretResult;
import java.util.UUID;

public interface RotateSecretUseCase {
    RotatedSecretResult rotate(UUID serial);
}
