package com.example.credentialcrypto.adapters.in.rest;

import com.example.credentialcrypto.application.port.in.GenerateAccessTokenUseCase;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;
    private final GenerateAccessTokenUseCase generateAccessTokenUseCase;

    public AuthenticationController(
            AuthenticationManager authenticationManager,
            GenerateAccessTokenUseCase generateAccessTokenUseCase
    ) {
        this.authenticationManager = authenticationManager;
        this.generateAccessTokenUseCase = generateAccessTokenUseCase;
    }

    @PostMapping("/token")
    @ResponseStatus(HttpStatus.OK)
    public AccessTokenResponse generateToken(@Valid @RequestBody GenerateAccessTokenRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(request.username(), request.password())
        );
        if (authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .noneMatch("ROLE_CLIENT"::equals)) {
            throw new org.springframework.security.authentication.BadCredentialsException(
                    "Credenciales no autorizadas."
            );
        }
        return AccessTokenResponse.from(generateAccessTokenUseCase.generate(authentication.getName()));
    }
}
