package com.example.credentialcrypto.application.port.out;

import java.time.Instant;
import java.util.List;

public interface AccessTokenSigningPort {
    String sign(String subject, List<String> roles, Instant issuedAt, Instant expiresAt);
}
