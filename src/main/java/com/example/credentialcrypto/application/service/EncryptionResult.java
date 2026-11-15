package com.example.credentialcrypto.application.service;

import com.example.credentialcrypto.domain.EncryptedPayload;
import com.example.credentialcrypto.domain.SecurityAssessment;

public record EncryptionResult(EncryptedPayload payload, SecurityAssessment securityAssessment) {
}
