package com.example.credentialcrypto.adapters.out.security;

import com.example.credentialcrypto.application.port.out.AccessTokenSigningPort;
import java.time.Instant;
import java.util.List;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.stereotype.Component;

@Component
public class NimbusAccessTokenSigningAdapter implements AccessTokenSigningPort {
    private final JwtEncoder jwtEncoder;
    private final JwtProperties properties;

    public NimbusAccessTokenSigningAdapter(JwtEncoder jwtEncoder, JwtProperties properties) {
        this.jwtEncoder = jwtEncoder;
        this.properties = properties;
    }

    @Override
    public String sign(String subject, List<String> roles, Instant issuedAt, Instant expiresAt) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.getIssuer())
                .subject(subject)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .claim("roles", roles)
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).type("JWT").build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
