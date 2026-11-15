package com.example.credentialcrypto.configuration;

import org.springframework.beans.factory.annotation.Value;
import com.example.credentialcrypto.adapters.out.security.JwtProperties;
import com.example.credentialcrypto.application.port.out.AccessTokenSigningPort;
import com.example.credentialcrypto.application.service.AccessTokenService;
import java.time.Duration;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import com.nimbusds.jose.jwk.source.ImmutableSecret;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class ApiSecurityConfiguration {
    @Bean
    public org.springframework.security.authentication.AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration
    ) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/v1/auth/token").permitAll()
                        .anyRequest().hasRole("CLIENT"))
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JwtProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(signingKey(properties))
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        decoder.setJwtValidator(
                org.springframework.security.oauth2.jwt.JwtValidators.createDefaultWithIssuer(properties.getIssuer())
        );
        return decoder;
    }

    @Bean
    public JwtEncoder jwtEncoder(JwtProperties properties) {
        return new NimbusJwtEncoder(new ImmutableSecret<>(signingKey(properties)));
    }

    @Bean
    public AccessTokenService accessTokenService(
            AccessTokenSigningPort signingPort,
            JwtProperties properties
    ) {
        if (properties.getExpirationSeconds() <= 0) {
            throw new IllegalStateException("credentials.jwt.expiration-seconds debe ser mayor que cero.");
        }
        return new AccessTokenService(signingPort, Duration.ofSeconds(properties.getExpirationSeconds()));
    }

    @Bean
    public UserDetailsService userDetailsService(
            @Value("${credentials.api.username:}") String username,
            @Value("${credentials.api.password:}") String password,
            PasswordEncoder passwordEncoder
    ) {
        if (username.isBlank() || password.isBlank()) {
            throw new IllegalStateException("Configure CREDENTIALS_API_USERNAME y CREDENTIALS_API_PASSWORD.");
        }
        return new InMemoryUserDetailsManager(
                User.withUsername(username).password(passwordEncoder.encode(password)).roles("CLIENT").build()
        );
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("roles");
        authoritiesConverter.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }

    private SecretKey signingKey(JwtProperties properties) {
        if (properties.getSecretBase64() == null || properties.getSecretBase64().isBlank()) {
            throw new IllegalStateException("Configure CREDENTIALS_JWT_SECRET_BASE64 con al menos 256 bits.");
        }
        try {
            byte[] key = Base64.getDecoder().decode(properties.getSecretBase64());
            if (key.length < 32) {
                throw new IllegalStateException("CREDENTIALS_JWT_SECRET_BASE64 debe contener al menos 256 bits.");
            }
            return new SecretKeySpec(key, "HmacSHA256");
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("CREDENTIALS_JWT_SECRET_BASE64 debe ser Base64 válido.", exception);
        }
    }
}
