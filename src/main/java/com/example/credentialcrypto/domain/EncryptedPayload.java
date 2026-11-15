package com.example.credentialcrypto.domain;

public record EncryptedPayload(
        int version,
        EncryptionAlgorithm algorithm,
        String nonce,
        String ciphertext,
        String encapsulatedKey,
        String kdfSalt
) {
}
