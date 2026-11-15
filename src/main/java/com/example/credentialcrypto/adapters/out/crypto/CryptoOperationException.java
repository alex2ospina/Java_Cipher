package com.example.credentialcrypto.adapters.out.crypto;

public class CryptoOperationException extends RuntimeException {
    public CryptoOperationException(String message) {
        super(message);
    }

    public CryptoOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}
