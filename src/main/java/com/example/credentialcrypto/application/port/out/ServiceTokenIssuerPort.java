package com.example.credentialcrypto.application.port.out;

public interface ServiceTokenIssuerPort {
    String rotate(String currentToken);
}
