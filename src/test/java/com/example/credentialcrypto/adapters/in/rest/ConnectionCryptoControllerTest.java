package com.example.credentialcrypto.adapters.in.rest;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.example.credentialcrypto.application.port.out.ServiceTokenIssuerPort;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

@SpringBootTest(properties = {
        "credentials.api.username=test-client",
        "credentials.api.password=test-password",
        "credentials.jwt.secret-base64=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "credentials.crypto.aes-key-base64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "spring.datasource.url=jdbc:sqlite::memory:",
        "spring.datasource.hikari.maximum-pool-size=1"
})
@AutoConfigureMockMvc
class ConnectionCryptoControllerTest {
    private static final KeyPair ML_KEM_KEY_PAIR = generateMlKemKeyPair();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoBean
    private ServiceTokenIssuerPort serviceTokenIssuerPort;

    @DynamicPropertySource
    static void registerMlKemKeys(DynamicPropertyRegistry registry) {
        registry.add(
                "credentials.crypto.ml-kem-public-key-base64",
                () -> Base64.getEncoder().encodeToString(ML_KEM_KEY_PAIR.getPublic().getEncoded())
        );
        registry.add(
                "credentials.crypto.ml-kem-private-key-base64",
                () -> Base64.getEncoder().encodeToString(ML_KEM_KEY_PAIR.getPrivate().getEncoded())
        );
    }

    private static KeyPair generateMlKemKeyPair() {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-KEM", "BC");
            generator.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());
            return generator.generateKeyPair();
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    private RequestPostProcessor bearerToken() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"test-client","password":"test-password"}
                                """))
                .andExpect(status().isOk())
                .andReturn();
        String token = objectMapper.readTree(result.getResponse().getContentAsString())
                .get("accessToken").asText();
        return request -> {
            request.addHeader("Authorization", "Bearer " + token);
            return request;
        };
    }

    @Test
    void issuesJwtForValidCredentials() throws Exception {
        mockMvc.perform(post("/api/v1/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"test-client","password":"test-password"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.issuedAt").isNotEmpty())
                .andExpect(jsonPath("$.expiresAt").isNotEmpty());
    }

    @Test
    void rejectsJwtIssuanceForInvalidCredentials() throws Exception {
        mockMvc.perform(post("/api/v1/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"test-client","password":"wrong-password"}
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsInvalidBearerToken() throws Exception {
        mockMvc.perform(post("/api/v1/connections/encrypt")
                        .header("Authorization", "Bearer not-a-valid-jwt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"db-user","password":"secret","algorithm":"AES_256_GCM"}
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void requiresAuthentication() throws Exception {
        mockMvc.perform(post("/api/v1/connections/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"db-user","password":"secret","algorithm":"AES_256_GCM"}
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void encryptsAndDecryptsCredentialsThroughApi() throws Exception {
        MvcResult encryptionResult = mockMvc.perform(post("/api/v1/connections/encrypt")
                        .with(bearerToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"db-user","password":"secret","algorithm":"AES_256_GCM"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.algorithm").value("AES_256_GCM"))
                .andExpect(jsonPath("$.securityAssessment.postQuantumResistant").value(false))
                .andReturn();

        mockMvc.perform(post("/api/v1/connections/decrypt")
                        .with(bearerToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(encryptionResult.getResponse().getContentAsString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("db-user"))
                .andExpect(jsonPath("$.password").value("secret"));
    }

    @Test
    void storesEncryptedPayloadAndDecryptsItUsingSerial() throws Exception {
        MvcResult storedResult = mockMvc.perform(post("/api/v1/connections")
                        .with(bearerToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"stored-user","password":"stored-secret","algorithm":"AES_256_GCM"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.serial").isNotEmpty())
                .andExpect(jsonPath("$.status").value("ENCRYPTED"))
                .andExpect(jsonPath("$.algorithm").value("AES_256_GCM"))
                .andExpect(jsonPath("$.ciphertext").isNotEmpty())
                .andExpect(jsonPath("$.nonce").isNotEmpty())
                .andReturn();

        String serial = objectMapper.readTree(storedResult.getResponse().getContentAsString())
                .get("serial")
                .asText();

        mockMvc.perform(post("/api/v1/connections/{serial}/decrypt", serial)
                        .with(bearerToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.serial").value(serial))
                .andExpect(jsonPath("$.status").value("ENCRYPTED"))
                .andExpect(jsonPath("$.username").value("stored-user"))
                .andExpect(jsonPath("$.password").value("stored-secret"));
    }

    @Test
    void returnsNotFoundForUnknownStoredSerial() throws Exception {
        mockMvc.perform(post("/api/v1/connections/{serial}/decrypt", "00000000-0000-0000-0000-000000000001")
                        .with(bearerToken()))
                .andExpect(status().isNotFound());
    }

    @Test
    void storesEncryptedServiceTokenAndDecryptsItUsingSerial() throws Exception {
        MvcResult storedResult = mockMvc.perform(post("/api/v1/connections/service-tokens")
                        .with(bearerToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"service-token-value","algorithm":"AES_256_GCM"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.serial").isNotEmpty())
                .andExpect(jsonPath("$.status").value("ENCRYPTED"))
                .andExpect(jsonPath("$.algorithm").value("AES_256_GCM"))
                .andExpect(jsonPath("$.ciphertext").isNotEmpty())
                .andReturn();

        String serial = objectMapper.readTree(storedResult.getResponse().getContentAsString())
                .get("serial")
                .asText();

        mockMvc.perform(post("/api/v1/connections/service-tokens/{serial}/decrypt", serial)
                        .with(bearerToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.serial").value(serial))
                .andExpect(jsonPath("$.status").value("ENCRYPTED"))
                .andExpect(jsonPath("$.token").value("service-token-value"));
    }

    @Test
    void seedsSecretWithExplicitIdentityAndOperation() throws Exception {
        mockMvc.perform(post("/api/v1/secrets/seed")
                        .with(bearerToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "identityType":"CONNECTION_CREDENTIALS",
                                  "username":"seeded-user",
                                  "password":"seeded-password",
                                  "algorithm":"AES_256_GCM"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.operation").value("SEEDED"))
                .andExpect(jsonPath("$.identityType").value("CONNECTION_CREDENTIALS"))
                .andExpect(jsonPath("$.status").value("ENCRYPTED"));
    }

    @Test
    void rejectsSeedRequestWithFieldsForWrongIdentityType() throws Exception {
        mockMvc.perform(post("/api/v1/secrets/seed")
                        .with(bearerToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "identityType":"CONNECTION_CREDENTIALS",
                                  "username":"seeded-user",
                                  "password":"seeded-password",
                                  "token":"should-not-be-here",
                                  "algorithm":"AES_256_GCM"
                                }
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rotatesConnectionPasswordWithPostQuantumEncryptionAndRemovesOldSerial() throws Exception {
        MvcResult initialResult = mockMvc.perform(post("/api/v1/connections")
                        .with(bearerToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"old-user","password":"old-password","algorithm":"AES_256_GCM"}
                                """))
                .andExpect(status().isCreated())
                .andReturn();
        String oldSerial = objectMapper.readTree(initialResult.getResponse().getContentAsString())
                .get("serial").asText();

        MvcResult rotationResult = mockMvc.perform(post("/api/v1/secrets/rotate")
                        .with(bearerToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of("serial", oldSerial))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.operation").value("ROTATED"))
                .andExpect(jsonPath("$.identityType").value("CONNECTION_CREDENTIALS"))
                .andExpect(jsonPath("$.status").value("ENCRYPTED"))
                .andExpect(jsonPath("$.algorithm").value("ML_KEM_768_AES_256_GCM"))
                .andExpect(jsonPath("$.username").value("old-user"))
                .andExpect(jsonPath("$.password").isNotEmpty())
                .andReturn();
        String newSerial = objectMapper.readTree(rotationResult.getResponse().getContentAsString())
                .get("serial").asText();
        String rotatedPassword = objectMapper.readTree(rotationResult.getResponse().getContentAsString())
                .get("password").asText();

        org.junit.jupiter.api.Assertions.assertNotEquals(oldSerial, newSerial);
        org.junit.jupiter.api.Assertions.assertNotEquals("old-password", rotatedPassword);
        org.junit.jupiter.api.Assertions.assertTrue(rotatedPassword.matches("(?s).*[A-Z].*"));
        org.junit.jupiter.api.Assertions.assertTrue(rotatedPassword.matches("(?s).*[a-z].*"));
        org.junit.jupiter.api.Assertions.assertTrue(rotatedPassword.matches("(?s).*[0-9].*"));
        org.junit.jupiter.api.Assertions.assertTrue(rotatedPassword.matches("(?s).*[^A-Za-z0-9].*"));
        mockMvc.perform(post("/api/v1/connections/{serial}/decrypt", oldSerial)
                        .with(bearerToken()))
                .andExpect(status().isNotFound());
        mockMvc.perform(post("/api/v1/connections/{serial}/decrypt", newSerial)
                        .with(bearerToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("old-user"))
                .andExpect(jsonPath("$.password").value(rotatedPassword));
    }

    @Test
    void rotatesServiceTokenUsingIssuerAndPostQuantumEncryption() throws Exception {
        MvcResult initialResult = mockMvc.perform(post("/api/v1/connections/service-tokens")
                        .with(bearerToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"old-service-token","algorithm":"AES_256_GCM"}
                                """))
                .andExpect(status().isCreated())
                .andReturn();
        String serial = objectMapper.readTree(initialResult.getResponse().getContentAsString())
                .get("serial").asText();

        when(serviceTokenIssuerPort.rotate("old-service-token")).thenReturn("new-service-token");

        MvcResult rotationResult = mockMvc.perform(post("/api/v1/secrets/rotate")
                        .with(bearerToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of("serial", serial))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.operation").value("ROTATED"))
                .andExpect(jsonPath("$.identityType").value("SERVICE_TOKEN"))
                .andExpect(jsonPath("$.algorithm").value("ML_KEM_768_AES_256_GCM"))
                .andExpect(jsonPath("$.token").value("new-service-token"))
                .andReturn();
        String newSerial = objectMapper.readTree(rotationResult.getResponse().getContentAsString())
                .get("serial").asText();
        verify(serviceTokenIssuerPort).rotate("old-service-token");

        mockMvc.perform(post("/api/v1/connections/service-tokens/{serial}/decrypt", serial)
                        .with(bearerToken()))
                .andExpect(status().isNotFound());
        mockMvc.perform(post("/api/v1/connections/service-tokens/{serial}/decrypt", newSerial)
                        .with(bearerToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("new-service-token"));
    }

    @Test
    void storesOnlyEncryptedMessageDataAndDecryptsBySerial() throws Exception {
        String plaintext = "mensaje secreto con acentos y emoji 🔐";
        MvcResult encryptionResult = mockMvc.perform(post("/api/v1/messages")
                        .with(bearerToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "message", plaintext,
                                "algorithm", "AES_256_GCM"
                        ))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.operation").value("ENCRYPTED"))
                .andExpect(jsonPath("$.status").value("ENCRYPTED"))
                .andExpect(jsonPath("$.algorithm").value("AES_256_GCM"))
                .andExpect(jsonPath("$.ciphertext").isNotEmpty())
                .andReturn();

        var storedResponse = objectMapper.readTree(encryptionResult.getResponse().getContentAsString());
        String serial = storedResponse.get("serial").asText();
        org.junit.jupiter.api.Assertions.assertNotEquals(plaintext, storedResponse.get("ciphertext").asText());

        String persistedCiphertext = jdbcTemplate.queryForObject(
                "SELECT ciphertext FROM encrypted_messages WHERE serial = ?",
                String.class,
                serial
        );
        org.junit.jupiter.api.Assertions.assertNotEquals(plaintext, persistedCiphertext);
        org.junit.jupiter.api.Assertions.assertEquals(1, jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM encrypted_messages WHERE serial = ?",
                Integer.class,
                serial
        ));

        mockMvc.perform(post("/api/v1/messages/{serial}/decrypt", serial)
                        .with(bearerToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.serial").value(serial))
                .andExpect(jsonPath("$.status").value("ENCRYPTED"))
                .andExpect(jsonPath("$.message").value(plaintext));
    }

    @Test
    void encryptsAndDecryptsMessageUsingPostQuantumAlgorithm() throws Exception {
        String plaintext = "mensaje protegido";
        MvcResult encryptionResult = mockMvc.perform(post("/api/v1/messages")
                        .with(bearerToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "message", plaintext,
                                "algorithm", "ML_KEM_768_AES_256_GCM"
                        ))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.algorithm").value("ML_KEM_768_AES_256_GCM"))
                .andExpect(jsonPath("$.encapsulatedKey").isNotEmpty())
                .andReturn();
        String serial = objectMapper.readTree(encryptionResult.getResponse().getContentAsString())
                .get("serial").asText();

        mockMvc.perform(post("/api/v1/messages/{serial}/decrypt", serial)
                        .with(bearerToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value(plaintext));
    }

    @Test
    void rejectsDecryptingUnknownMessageSerial() throws Exception {
        mockMvc.perform(post(
                                "/api/v1/messages/{serial}/decrypt",
                                "00000000-0000-0000-0000-000000000002"
                        )
                        .with(bearerToken()))
                .andExpect(status().isNotFound());
    }
}
