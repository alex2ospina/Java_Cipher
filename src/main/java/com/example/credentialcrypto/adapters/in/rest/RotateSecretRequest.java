package com.example.credentialcrypto.adapters.in.rest;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record RotateSecretRequest(@NotNull UUID serial) {
}
