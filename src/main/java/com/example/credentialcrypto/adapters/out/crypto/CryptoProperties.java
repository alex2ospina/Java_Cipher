package com.example.credentialcrypto.adapters.out.crypto;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "credentials.crypto")
public class CryptoProperties {
    private String aesKeyBase64;
    private String mlKemPublicKeyBase64;
    private String mlKemPrivateKeyBase64;

    public String getAesKeyBase64() {
        return aesKeyBase64;
    }

    public void setAesKeyBase64(String aesKeyBase64) {
        this.aesKeyBase64 = aesKeyBase64;
    }

    public String getMlKemPublicKeyBase64() {
        return mlKemPublicKeyBase64;
    }

    public void setMlKemPublicKeyBase64(String mlKemPublicKeyBase64) {
        this.mlKemPublicKeyBase64 = mlKemPublicKeyBase64;
    }

    public String getMlKemPrivateKeyBase64() {
        return mlKemPrivateKeyBase64;
    }

    public void setMlKemPrivateKeyBase64(String mlKemPrivateKeyBase64) {
        this.mlKemPrivateKeyBase64 = mlKemPrivateKeyBase64;
    }
}
