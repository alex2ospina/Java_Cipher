package com.example.credentialcrypto.adapters.out.persistence;

import com.example.credentialcrypto.application.port.out.MessageArchivePort;
import com.example.credentialcrypto.domain.EncryptedPayload;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.EncryptionStatus;
import com.example.credentialcrypto.domain.StoredMessage;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class SqliteMessageArchiveAdapter implements MessageArchivePort {
    private static final String INSERT_SQL = """
            INSERT INTO encrypted_messages (
                serial, status, payload_version, algorithm, nonce, ciphertext,
                encapsulated_key, kdf_salt, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private static final String SELECT_BY_SERIAL_SQL = """
            SELECT serial, status, payload_version, algorithm, nonce, ciphertext,
                   encapsulated_key, kdf_salt, created_at
            FROM encrypted_messages
            WHERE serial = ?
            """;

    private static final RowMapper<StoredMessage> ROW_MAPPER = SqliteMessageArchiveAdapter::mapRow;

    private final JdbcTemplate jdbcTemplate;

    public SqliteMessageArchiveAdapter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void save(StoredMessage message) {
        EncryptedPayload payload = message.payload();
        jdbcTemplate.update(
                INSERT_SQL,
                message.serial().toString(),
                message.status().name(),
                payload.version(),
                payload.algorithm().name(),
                payload.nonce(),
                payload.ciphertext(),
                payload.encapsulatedKey(),
                payload.kdfSalt(),
                Timestamp.from(message.createdAt())
        );
    }

    @Override
    public Optional<StoredMessage> findBySerial(UUID serial) {
        return jdbcTemplate.query(SELECT_BY_SERIAL_SQL, ROW_MAPPER, serial.toString())
                .stream()
                .findFirst();
    }

    private static StoredMessage mapRow(ResultSet resultSet, int rowNumber) throws SQLException {
        EncryptedPayload payload = new EncryptedPayload(
                resultSet.getInt("payload_version"),
                EncryptionAlgorithm.valueOf(resultSet.getString("algorithm")),
                resultSet.getString("nonce"),
                resultSet.getString("ciphertext"),
                resultSet.getString("encapsulated_key"),
                resultSet.getString("kdf_salt")
        );
        return new StoredMessage(
                UUID.fromString(resultSet.getString("serial")),
                EncryptionStatus.valueOf(resultSet.getString("status")),
                payload,
                resultSet.getTimestamp("created_at").toInstant()
        );
    }
}
