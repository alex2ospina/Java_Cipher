package com.example.credentialcrypto.adapters.out.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.credentialcrypto.domain.ConnectionCredentials;
import com.example.credentialcrypto.domain.EncryptedPayload;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.SecurityAssessment;
import com.example.credentialcrypto.domain.SecurityLevel;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BouncyCastleCredentialCryptoAdapterTest {
    private static KeyPair mlKemKeyPair;
    private BouncyCastleCredentialCryptoAdapter adapter;

    @BeforeAll
    static void generateMlKemKeyPair() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-KEM", "BC");
        generator.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
        mlKemKeyPair = generator.generateKeyPair();
    }

    @BeforeEach
    void setUp() {
        CryptoProperties properties = new CryptoProperties();
        properties.setAesKeyBase64(Base64.getEncoder().encodeToString(new byte[32]));
        properties.setMlKemPublicKeyBase64(Base64.getEncoder().encodeToString(mlKemKeyPair.getPublic().getEncoded()));
        properties.setMlKemPrivateKeyBase64(Base64.getEncoder().encodeToString(mlKemKeyPair.getPrivate().getEncoded()));
        adapter = new BouncyCastleCredentialCryptoAdapter(properties, new ObjectMapper());
    }

    @Test
    void encryptsAndDecryptsWithAes256Gcm() {
        ConnectionCredentials credentials = new ConnectionCredentials("db-user", "pass-123");

        EncryptedPayload payload = adapter.encrypt(credentials, EncryptionAlgorithm.AES_256_GCM);

        assertNotEquals("pass-123", payload.ciphertext());
        assertEquals(credentials, adapter.decrypt(payload));
        assertEquals(SecurityLevel.HIGH,
                SecurityAssessment.forAlgorithm(EncryptionAlgorithm.AES_256_GCM).level());
        assertFalse(SecurityAssessment.forAlgorithm(EncryptionAlgorithm.AES_256_GCM).postQuantumResistant());
    }

    @Test
    void encryptsAndDecryptsWithHybridMlKemAndAes() {
        ConnectionCredentials credentials = new ConnectionCredentials("db-user", "pass-123");

        EncryptedPayload payload = adapter.encrypt(credentials, EncryptionAlgorithm.ML_KEM_768_AES_256_GCM);

        assertNotEquals("pass-123", payload.ciphertext());
        assertEquals(credentials, adapter.decrypt(payload));
        assertEquals(3, SecurityAssessment.forAlgorithm(payload.algorithm()).nistPqcCategory());
        assertTrue(SecurityAssessment.forAlgorithm(payload.algorithm()).postQuantumResistant());
    }

    @Test
    void rejectsTamperedCiphertext() {
        EncryptedPayload payload = adapter.encrypt(
                new ConnectionCredentials("db-user", "pass-123"),
                EncryptionAlgorithm.AES_256_GCM
        );
        String tamperedCiphertext = payload.ciphertext().substring(0, payload.ciphertext().length() - 2) + "AA";
        EncryptedPayload tampered = new EncryptedPayload(
                payload.version(),
                payload.algorithm(),
                payload.nonce(),
                tamperedCiphertext,
                payload.encapsulatedKey(),
                payload.kdfSalt()
        );

        assertThrows(CryptoOperationException.class, () -> adapter.decrypt(tampered));
    }

    @Test
    void encryptsAndDecryptsServiceTokenWithAes() {
        String token = "svc-token/á-123+==";

        EncryptedPayload payload = adapter.encryptServiceToken(token, EncryptionAlgorithm.AES_256_GCM);

        assertNotEquals(token, payload.ciphertext());
        assertEquals(token, adapter.decryptServiceToken(payload));
    }

    @Test
    void encryptsAndDecryptsServiceTokenWithHybridMlKem() {
        String token = "service-token-value";

        EncryptedPayload payload = adapter.encryptServiceToken(
                token,
                EncryptionAlgorithm.ML_KEM_768_AES_256_GCM
        );

        assertEquals(token, adapter.decryptServiceToken(payload));
    }

    @Test
    void doesNotAllowDecryptingCredentialEnvelopeAsServiceToken() {
        EncryptedPayload payload = adapter.encrypt(
                new ConnectionCredentials("db-user", "pass-123"),
                EncryptionAlgorithm.AES_256_GCM
        );

        assertThrows(CryptoOperationException.class, () -> adapter.decryptServiceToken(payload));
    }

    @Test
    void encryptsAndDecryptsMessageWithAesAndUnicode() {
        String message = "Mensaje privado: cifrado 🔐";

        EncryptedPayload payload = adapter.encryptMessage(message, EncryptionAlgorithm.AES_256_GCM);

        assertNotEquals(message, payload.ciphertext());
        assertEquals(message, adapter.decryptMessage(payload));
    }

    @Test
    void encryptsAndDecryptsMessageWithPostQuantumHybrid() {
        String message = "mensaje postcuántico";

        EncryptedPayload payload = adapter.encryptMessage(
                message,
                EncryptionAlgorithm.ML_KEM_768_AES_256_GCM
        );

        assertEquals(message, adapter.decryptMessage(payload));
    }

    @Test
    void doesNotAllowDecryptingTokenEnvelopeAsMessage() {
        EncryptedPayload payload = adapter.encryptServiceToken("service-token", EncryptionAlgorithm.AES_256_GCM);

        assertThrows(CryptoOperationException.class, () -> adapter.decryptMessage(payload));
    }
}
