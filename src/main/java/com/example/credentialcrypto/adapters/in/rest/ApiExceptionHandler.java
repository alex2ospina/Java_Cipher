package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.adapters.out.crypto.CryptoConfigurationException;
import com.example.credentialcrypto.adapters.out.crypto.CryptoOperationException;
import com.example.credentialcrypto.application.service.ConnectionNotFoundException;
import com.example.credentialcrypto.application.service.ServiceTokenIssuerUnavailableException;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidation(MethodArgumentNotValidException exception) {
        return ResponseEntity.badRequest().body(Map.of("error", "La solicitud contiene campos inválidos."));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, String>> handleAuthentication(AuthenticationException exception) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Credenciales inválidas."));
    }

    @ExceptionHandler(CryptoConfigurationException.class)
    public ResponseEntity<Map<String, String>> handleConfiguration(CryptoConfigurationException exception) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of("error", exception.getMessage()));
    }

    @ExceptionHandler(CryptoOperationException.class)
    public ResponseEntity<Map<String, String>> handleCryptoOperation(CryptoOperationException exception) {
        return ResponseEntity.badRequest().body(Map.of("error", exception.getMessage()));
    }

    @ExceptionHandler(ConnectionNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleConnectionNotFound(ConnectionNotFoundException exception) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", exception.getMessage()));
    }

    @ExceptionHandler(ServiceTokenIssuerUnavailableException.class)
    public ResponseEntity<Map<String, String>> handleTokenIssuerUnavailable(
            ServiceTokenIssuerUnavailableException exception
    ) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of("error", exception.getMessage()));
    }
}
