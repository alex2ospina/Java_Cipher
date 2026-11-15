package com.example.credentialcrypto.application.service;

import java.util.UUID;

public class ConnectionNotFoundException extends RuntimeException {
    public ConnectionNotFoundException(UUID serial) {
        super("No se encontró un registro cifrado con el serial solicitado.");
    }
}
