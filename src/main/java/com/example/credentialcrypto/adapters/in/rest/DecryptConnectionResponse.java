package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.domain.ConnectionCredentials;

public record DecryptConnectionResponse(String username, String password) {
    public static DecryptConnectionResponse from(ConnectionCredentials credentials) {
        return new DecryptConnectionResponse(credentials.username(), credentials.password());
    }
}
