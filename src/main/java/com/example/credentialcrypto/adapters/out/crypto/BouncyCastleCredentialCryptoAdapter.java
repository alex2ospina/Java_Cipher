package com.example.credentialcrypto.adapters.out.crypto;

import com.example.credentialcrypto.application.port.out.CredentialCryptoPort;
import com.example.credentialcrypto.domain.ConnectionCredentials;
import com.example.credentialcrypto.domain.EncryptedPayload;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.springframework.stereotype.Component;

@Component
public class BouncyCastleCredentialCryptoAdapter implements CredentialCryptoPort {
    private static final int NONCE_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int AES_KEY_LENGTH_BYTES = 32;
    private static final int KDF_SALT_LENGTH_BYTES = 32;
    private static final int VERSION = 1;
    private static final String CREDENTIALS_CONTEXT = "connection-credentials";
    private static final String SERVICE_TOKEN_CONTEXT = "service-token";
    private static final String MESSAGE_CONTEXT = "message";

    private final CryptoProperties properties;
    private final ObjectMapper objectMapper;
    private final SecureRandom secureRandom;

    public BouncyCastleCredentialCryptoAdapter(CryptoProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.secureRandom = new SecureRandom();
    }

    @Override
    public EncryptedPayload encrypt(ConnectionCredentials credentials, EncryptionAlgorithm algorithm) {
        byte[] plaintext = null;
        try {
            plaintext = objectMapper.writeValueAsBytes(credentials);
            return encryptPayload(plaintext, algorithm, CREDENTIALS_CONTEXT);
        } catch (CryptoConfigurationException | CryptoOperationException exception) {
            throw exception;
        } catch (JsonProcessingException exception) {
            throw new CryptoOperationException("No se pudieron serializar las credenciales.", exception);
        } finally {
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    @Override
    public ConnectionCredentials decrypt(EncryptedPayload payload) {
        byte[] plaintext = null;
        try {
            plaintext = decryptPayload(payload, CREDENTIALS_CONTEXT);
            return objectMapper.readValue(plaintext, ConnectionCredentials.class);
        } catch (CryptoConfigurationException | CryptoOperationException exception) {
            throw exception;
        } catch (GeneralSecurityException | IOException | IllegalArgumentException exception) {
            throw new CryptoOperationException("No se pudieron descifrar las credenciales.", exception);
        } finally {
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    @Override
    public EncryptedPayload encryptServiceToken(String token, EncryptionAlgorithm algorithm) {
        byte[] plaintext = token.getBytes(StandardCharsets.UTF_8);
        try {
            return encryptPayload(plaintext, algorithm, SERVICE_TOKEN_CONTEXT);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    @Override
    public String decryptServiceToken(EncryptedPayload payload) {
        byte[] plaintext = null;
        try {
            plaintext = decryptPayload(payload, SERVICE_TOKEN_CONTEXT);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new CryptoOperationException("No se pudo descifrar el token de servicio.", exception);
        } finally {
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    @Override
    public EncryptedPayload encryptMessage(String message, EncryptionAlgorithm algorithm) {
        byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
        try {
            return encryptPayload(plaintext, algorithm, MESSAGE_CONTEXT);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    @Override
    public String decryptMessage(EncryptedPayload payload) {
        byte[] plaintext = null;
        try {
            plaintext = decryptPayload(payload, MESSAGE_CONTEXT);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new CryptoOperationException("No se pudo descifrar el mensaje.", exception);
        } finally {
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    private EncryptedPayload encryptPayload(byte[] plaintext, EncryptionAlgorithm algorithm, String context) {
        return switch (algorithm) {
            case AES_256_GCM -> encryptAes(plaintext, algorithm, context);
            case ML_KEM_768_AES_256_GCM -> encryptHybrid(plaintext, algorithm, context);
        };
    }

    private byte[] decryptPayload(EncryptedPayload payload, String context) throws GeneralSecurityException {
        validatePayload(payload);
        return switch (payload.algorithm()) {
            case AES_256_GCM -> decryptAes(payload, context);
            case ML_KEM_768_AES_256_GCM -> decryptHybrid(payload, context);
        };
    }

    private EncryptedPayload encryptAes(byte[] plaintext, EncryptionAlgorithm algorithm, String context) {
        byte[] nonce = randomBytes(NONCE_LENGTH_BYTES);
        byte[] key = aesKey();
        try {
            byte[] ciphertext = encryptAesGcm(plaintext, key, nonce, aad(algorithm, context));
            return new EncryptedPayload(
                    VERSION,
                    algorithm,
                    encode(nonce),
                    encode(ciphertext),
                    null,
                    null
            );
        } catch (GeneralSecurityException exception) {
            throw new CryptoOperationException("No se pudieron cifrar los datos.", exception);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private EncryptedPayload encryptHybrid(byte[] plaintext, EncryptionAlgorithm algorithm, String context) {
        MLKEMPublicKeyParameters publicKey = mlKemPublicKey();
        byte[] salt = randomBytes(KDF_SALT_LENGTH_BYTES);
        byte[] nonce = randomBytes(NONCE_LENGTH_BYTES);
        SecretWithEncapsulation encapsulated = new MLKEMGenerator(secureRandom).generateEncapsulated(publicKey);
        byte[] sharedSecret = null;
        byte[] aesKey = null;
        try {
            sharedSecret = encapsulated.getSecret();
            aesKey = hkdf(sharedSecret, salt, hkdfInfo(algorithm, context));
            byte[] ciphertext = encryptAesGcm(
                    plaintext, aesKey, nonce, aad(algorithm, context));
            return new EncryptedPayload(
                    VERSION,
                    algorithm,
                    encode(nonce),
                    encode(ciphertext),
                    encode(encapsulated.getEncapsulation()),
                    encode(salt)
            );
        } catch (GeneralSecurityException | IllegalStateException exception) {
            throw new CryptoOperationException("No se pudieron cifrar los datos.", exception);
        } finally {
            if (sharedSecret != null) {
                Arrays.fill(sharedSecret, (byte) 0);
            }
            if (aesKey != null) {
                Arrays.fill(aesKey, (byte) 0);
            }
            try {
                encapsulated.destroy();
            } catch (DestroyFailedException exception) {
                throw new CryptoOperationException("No se pudo limpiar el secreto encapsulado.", exception);
            }
        }
    }

    private byte[] decryptAes(EncryptedPayload payload, String context) throws GeneralSecurityException {
        byte[] key = aesKey();
        try {
            return decryptAesGcm(
                    decode(payload.ciphertext()),
                    key,
                    decode(payload.nonce()),
                    aad(payload.algorithm(), context)
            );
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private byte[] decryptHybrid(EncryptedPayload payload, String context) throws GeneralSecurityException {
        byte[] salt = decode(payload.kdfSalt());
        byte[] sharedSecret = new MLKEMExtractor(mlKemPrivateKey()).extractSecret(decode(payload.encapsulatedKey()));
        byte[] aesKey = null;
        try {
            aesKey = hkdf(sharedSecret, salt, hkdfInfo(payload.algorithm(), context));
            return decryptAesGcm(
                    decode(payload.ciphertext()),
                    aesKey,
                    decode(payload.nonce()),
                    aad(payload.algorithm(), context)
            );
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            if (aesKey != null) {
                Arrays.fill(aesKey, (byte) 0);
            }
        }
    }

    private byte[] encryptAesGcm(byte[] plaintext, byte[] key, byte[] nonce, byte[] aad)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    private byte[] decryptAesGcm(byte[] ciphertext, byte[] key, byte[] nonce, byte[] aad)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(ciphertext);
    }

    private byte[] aesKey() {
        return decodeConfiguredKey(properties.getAesKeyBase64(), AES_KEY_LENGTH_BYTES, "CREDENTIALS_AES_KEY_BASE64");
    }

    private MLKEMPublicKeyParameters mlKemPublicKey() {
        String configuredKey = properties.getMlKemPublicKeyBase64();
        if (configuredKey == null || configuredKey.isBlank()) {
            throw new CryptoConfigurationException("Falta configurar CREDENTIALS_MLKEM_PUBLIC_KEY_BASE64.");
        }
        try {
            var keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(configuredKey));
            var key = KeyFactory.getInstance("ML-KEM", new BouncyCastleProvider()).generatePublic(keySpec);
            if (key instanceof MLKEMPublicKey mlKemKey
                    && "ML-KEM-768".equals(mlKemKey.getParameterSpec().getName())) {
                return new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, mlKemKey.getPublicData());
            }
            throw new CryptoConfigurationException("La clave pública debe ser ML-KEM-768 en formato X.509.");
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new CryptoConfigurationException("La clave pública ML-KEM no es un X.509 Base64 válido.", exception);
        }
    }

    private MLKEMPrivateKeyParameters mlKemPrivateKey() {
        String configuredKey = properties.getMlKemPrivateKeyBase64();
        if (configuredKey == null || configuredKey.isBlank()) {
            throw new CryptoConfigurationException("Falta configurar CREDENTIALS_MLKEM_PRIVATE_KEY_BASE64.");
        }
        try {
            var keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(configuredKey));
            var key = KeyFactory.getInstance("ML-KEM", new BouncyCastleProvider()).generatePrivate(keySpec);
            if (key instanceof MLKEMPrivateKey mlKemKey
                    && "ML-KEM-768".equals(mlKemKey.getParameterSpec().getName())) {
                return new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, mlKemKey.getPrivateData());
            }
            throw new CryptoConfigurationException("La clave privada debe ser ML-KEM-768 en formato PKCS#8.");
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new CryptoConfigurationException("La clave privada ML-KEM no es un PKCS#8 Base64 válido.", exception);
        }
    }

    private byte[] decodeConfiguredKey(String configuredKey, int expectedLength, String variableName) {
        if (configuredKey == null || configuredKey.isBlank()) {
            throw new CryptoConfigurationException("Falta configurar " + variableName + ".");
        }
        try {
            byte[] key = Base64.getDecoder().decode(configuredKey);
            if (key.length != expectedLength) {
                throw new CryptoConfigurationException(variableName + " debe representar una clave de 256 bits.");
            }
            return key;
        } catch (IllegalArgumentException exception) {
            throw new CryptoConfigurationException(variableName + " debe estar codificada en Base64 válido.", exception);
        }
    }

    private byte[] hkdf(byte[] inputKeyMaterial, byte[] salt, byte[] info) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] pseudorandomKey = mac.doFinal(inputKeyMaterial);
        try {
            mac.init(new SecretKeySpec(pseudorandomKey, "HmacSHA256"));
            mac.update(info);
            mac.update((byte) 1);
            return Arrays.copyOf(mac.doFinal(), AES_KEY_LENGTH_BYTES);
        } finally {
            Arrays.fill(pseudorandomKey, (byte) 0);
        }
    }

    private byte[] hkdfInfo(EncryptionAlgorithm algorithm, String context) {
        return (context + ":v1:" + algorithm.name()).getBytes(StandardCharsets.UTF_8);
    }

    private byte[] aad(EncryptionAlgorithm algorithm, String context) {
        byte[] prefix = (context + ":v1:").getBytes(StandardCharsets.UTF_8);
        byte[] algorithmBytes = algorithm.name().getBytes(StandardCharsets.UTF_8);
        byte[] aad = Arrays.copyOf(prefix, prefix.length + algorithmBytes.length);
        System.arraycopy(algorithmBytes, 0, aad, prefix.length, algorithmBytes.length);
        return aad;
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    private String encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private byte[] decode(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException exception) {
            throw new CryptoOperationException("El sobre cifrado contiene un campo Base64 inválido.", exception);
        }
    }

    private void validatePayload(EncryptedPayload payload) {
        if (payload == null || payload.version() != VERSION || payload.algorithm() == null) {
            throw new CryptoOperationException("La versión o el algoritmo del sobre cifrado no son válidos.");
        }
        if (isBlank(payload.nonce()) || isBlank(payload.ciphertext())) {
            throw new CryptoOperationException("El sobre cifrado no contiene nonce y ciphertext válidos.");
        }
        if (payload.algorithm() == EncryptionAlgorithm.ML_KEM_768_AES_256_GCM
                && (isBlank(payload.encapsulatedKey()) || isBlank(payload.kdfSalt()))) {
            throw new CryptoOperationException("El sobre híbrido no contiene la clave encapsulada y la sal KDF.");
        }
        if (payload.algorithm() == EncryptionAlgorithm.AES_256_GCM
                && (payload.encapsulatedKey() != null || payload.kdfSalt() != null)) {
            throw new CryptoOperationException("El sobre AES-256-GCM no debe contener campos de encapsulación.");
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
