package com.example.credentialcrypto.application.port.in;

import com.example.credentialcrypto.domain.AccessToken;

public interface GenerateAccessTokenUseCase {
    AccessToken generate(String subject);
}
