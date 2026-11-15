package com.example.credentialcrypto.domain;

import java.time.Instant;

public record AccessToken(String value, Instant issuedAt, Instant expiresAt) {
}
