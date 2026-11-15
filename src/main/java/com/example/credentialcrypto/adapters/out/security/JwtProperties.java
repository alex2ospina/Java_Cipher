package com.example.credentialcrypto.adapters.out.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "credentials.jwt")
public class JwtProperties {
    private String secretBase64;
    private String issuer = "connection-credential-crypto";
    private long expirationSeconds = 900;

    public String getSecretBase64() {
        return secretBase64;
    }

    public void setSecretBase64(String secretBase64) {
        this.secretBase64 = secretBase64;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public long getExpirationSeconds() {
        return expirationSeconds;
    }

    public void setExpirationSeconds(long expirationSeconds) {
        this.expirationSeconds = expirationSeconds;
    }
}
