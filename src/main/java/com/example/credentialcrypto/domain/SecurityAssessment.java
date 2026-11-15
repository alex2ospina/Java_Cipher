package com.example.credentialcrypto.domain;

public record SecurityAssessment(
        SecurityLevel level,
        boolean postQuantumResistant,
        Integer nistPqcCategory,
        String rationale
) {
    public static SecurityAssessment forAlgorithm(EncryptionAlgorithm algorithm) {
        return switch (algorithm) {
            case AES_256_GCM -> new SecurityAssessment(
                    SecurityLevel.HIGH,
                    false,
                    null,
                    "AES-256-GCM ofrece seguridad simétrica fuerte; no es resistente a ataques cuánticos."
            );
            case ML_KEM_768_AES_256_GCM -> new SecurityAssessment(
                    SecurityLevel.HIGH,
                    true,
                    3,
                    "ML-KEM-768 (categoría NIST 3) establece la clave; AES-256-GCM cifra y autentica los datos."
            );
        };
    }
}
