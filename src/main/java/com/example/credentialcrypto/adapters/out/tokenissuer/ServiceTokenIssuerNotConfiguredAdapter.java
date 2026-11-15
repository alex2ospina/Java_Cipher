package com.example.credentialcrypto.adapters.out.tokenissuer;

import com.example.credentialcrypto.application.port.out.ServiceTokenIssuerPort;
import com.example.credentialcrypto.application.service.ServiceTokenIssuerUnavailableException;
import org.springframework.stereotype.Component;

@Component
public class ServiceTokenIssuerNotConfiguredAdapter implements ServiceTokenIssuerPort {
    @Override
    public String rotate(String currentToken) {
        throw new ServiceTokenIssuerUnavailableException(
                "La integración con el emisor de tokens aún no está configurada."
        );
    }
}
