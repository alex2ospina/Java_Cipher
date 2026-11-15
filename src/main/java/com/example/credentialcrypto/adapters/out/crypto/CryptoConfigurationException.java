package com.example.credentialcrypto.adapters.out.crypto;

public class CryptoConfigurationException extends RuntimeException {
    public CryptoConfigurationException(String message) {
        super(message);
    }

    public CryptoConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
