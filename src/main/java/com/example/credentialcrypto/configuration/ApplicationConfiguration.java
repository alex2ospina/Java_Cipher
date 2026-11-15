package com.example.credentialcrypto.configuration;

import com.example.credentialcrypto.adapters.out.crypto.CryptoProperties;
import com.example.credentialcrypto.application.port.out.ConnectionArchivePort;
import com.example.credentialcrypto.application.port.out.CredentialCryptoPort;
import com.example.credentialcrypto.application.port.out.MessageArchivePort;
import com.example.credentialcrypto.application.port.out.ServiceTokenArchivePort;
import com.example.credentialcrypto.application.port.out.ServiceTokenIssuerPort;
import com.example.credentialcrypto.application.service.MessageManagementService;
import com.example.credentialcrypto.application.service.SecretManagementService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(CryptoProperties.class)
public class ApplicationConfiguration {
    @Bean
    public SecretManagementService secretManagementService(
            CredentialCryptoPort cryptoPort,
            ConnectionArchivePort archivePort,
            ServiceTokenArchivePort serviceTokenArchivePort,
            ServiceTokenIssuerPort serviceTokenIssuerPort
    ) {
        return new SecretManagementService(
                cryptoPort, archivePort, serviceTokenArchivePort, serviceTokenIssuerPort);
    }

    @Bean
    public MessageManagementService messageManagementService(
            CredentialCryptoPort cryptoPort,
            MessageArchivePort archivePort
    ) {
        return new MessageManagementService(cryptoPort, archivePort);
    }
}
