package com.example.credentialcrypto.adapters.out.persistence;

import com.example.credentialcrypto.application.port.out.ConnectionArchivePort;
import com.example.credentialcrypto.domain.EncryptedPayload;
import com.example.credentialcrypto.domain.EncryptionAlgorithm;
import com.example.credentialcrypto.domain.EncryptionStatus;
import com.example.credentialcrypto.domain.StoredConnection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class SqliteConnectionArchiveAdapter implements ConnectionArchivePort {
    private static final String INSERT_SQL = """
            INSERT INTO encrypted_connections (
                serial, status, payload_version, algorithm, nonce, ciphertext,
                encapsulated_key, kdf_salt, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private static final String SELECT_BY_SERIAL_SQL = """
            SELECT serial, status, payload_version, algorithm, nonce, ciphertext,
                   encapsulated_key, kdf_salt, created_at
            FROM encrypted_connections
            WHERE serial = ?
            """;

    private static final RowMapper<StoredConnection> ROW_MAPPER = SqliteConnectionArchiveAdapter::mapRow;

    private final JdbcTemplate jdbcTemplate;

    public SqliteConnectionArchiveAdapter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void save(StoredConnection connection) {
        EncryptedPayload payload = connection.payload();
        jdbcTemplate.update(
                INSERT_SQL,
                connection.serial().toString(),
                connection.status().name(),
                payload.version(),
                payload.algorithm().name(),
                payload.nonce(),
                payload.ciphertext(),
                payload.encapsulatedKey(),
                payload.kdfSalt(),
                Timestamp.from(connection.createdAt())
        );
    }

    @Override
    public Optional<StoredConnection> findBySerial(UUID serial) {
        return jdbcTemplate.query(SELECT_BY_SERIAL_SQL, ROW_MAPPER, serial.toString())
                .stream()
                .findFirst();
    }

    @Override
    @Transactional
    public boolean replace(UUID oldSerial, StoredConnection replacement) {
        int deleted = jdbcTemplate.update(
                "DELETE FROM encrypted_connections WHERE serial = ?",
                oldSerial.toString()
        );
        if (deleted == 0) {
            return false;
        }
        save(replacement);
        return true;
    }

    private static StoredConnection mapRow(ResultSet resultSet, int rowNumber) throws SQLException {
        EncryptedPayload payload = new EncryptedPayload(
                resultSet.getInt("payload_version"),
                EncryptionAlgorithm.valueOf(resultSet.getString("algorithm")),
                resultSet.getString("nonce"),
                resultSet.getString("ciphertext"),
                resultSet.getString("encapsulated_key"),
                resultSet.getString("kdf_salt")
        );
        return new StoredConnection(
                UUID.fromString(resultSet.getString("serial")),
                EncryptionStatus.valueOf(resultSet.getString("status")),
                payload,
                resultSet.getTimestamp("created_at").toInstant()
        );
    }
}
