package com.example.credentialcrypto.adapters.out.persistence;

import com.example.credentialcrypto.application.port.out.ServiceTokenArchivePort;
import com.example.credentialcrypto.domain.EncryptedPayload;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.EncryptionStatus;
import com.example.credentialcrypto.domain.StoredServiceToken;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class SqliteServiceTokenArchiveAdapter implements ServiceTokenArchivePort {
    private static final String INSERT_SQL = """
            INSERT INTO encrypted_service_tokens (
                serial, status, payload_version, algorithm, nonce, ciphertext,
                encapsulated_key, kdf_salt, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private static final String SELECT_BY_SERIAL_SQL = """
            SELECT serial, status, payload_version, algorithm, nonce, ciphertext,
                   encapsulated_key, kdf_salt, created_at
            FROM encrypted_service_tokens
            WHERE serial = ?
            """;

    private static final RowMapper<StoredServiceToken> ROW_MAPPER =
            SqliteServiceTokenArchiveAdapter::mapRow;

    private final JdbcTemplate jdbcTemplate;

    public SqliteServiceTokenArchiveAdapter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void save(StoredServiceToken token) {
        EncryptedPayload payload = token.payload();
        jdbcTemplate.update(
                INSERT_SQL,
                token.serial().toString(),
                token.status().name(),
                payload.version(),
                payload.algorithm().name(),
                payload.nonce(),
                payload.ciphertext(),
                payload.encapsulatedKey(),
                payload.kdfSalt(),
                Timestamp.from(token.createdAt())
        );
    }

    @Override
    public Optional<StoredServiceToken> findBySerial(UUID serial) {
        return jdbcTemplate.query(SELECT_BY_SERIAL_SQL, ROW_MAPPER, serial.toString())
                .stream()
                .findFirst();
    }

    @Override
    @Transactional
    public boolean replace(UUID oldSerial, StoredServiceToken replacement) {
        int deleted = jdbcTemplate.update(
                "DELETE FROM encrypted_service_tokens WHERE serial = ?",
                oldSerial.toString()
        );
        if (deleted == 0) {
            return false;
        }
        save(replacement);
        return true;
    }

    private static StoredServiceToken mapRow(ResultSet resultSet, int rowNumber) throws SQLException {
        EncryptedPayload payload = new EncryptedPayload(
                resultSet.getInt("payload_version"),
                EncryptionAlgorithm.valueOf(resultSet.getString("algorithm")),
                resultSet.getString("nonce"),
                resultSet.getString("ciphertext"),
                resultSet.getString("encapsulated_key"),
                resultSet.getString("kdf_salt")
        );
        return new StoredServiceToken(
                UUID.fromString(resultSet.getString("serial")),
                EncryptionStatus.valueOf(resultSet.getString("status")),
                payload,
                resultSet.getTimestamp("created_at").toInstant()
        );
    }
}
