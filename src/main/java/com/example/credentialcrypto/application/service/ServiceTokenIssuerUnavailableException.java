package com.example.credentialcrypto.application.service;

public class ServiceTokenIssuerUnavailableException extends RuntimeException {
    public ServiceTokenIssuerUnavailableException(String message) {
        super(message);
    }
}
