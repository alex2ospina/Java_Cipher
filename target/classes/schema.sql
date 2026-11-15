CREATE TABLE IF NOT EXISTS encrypted_connections (
    serial TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL CHECK (status = 'ENCRYPTED'),
    payload_version INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    encapsulated_key TEXT,
    kdf_salt TEXT,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS encrypted_service_tokens (
    serial TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL CHECK (status = 'ENCRYPTED'),
    payload_version INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    encapsulated_key TEXT,
    kdf_salt TEXT,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS encrypted_messages (
    serial TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL CHECK (status = 'ENCRYPTED'),
    payload_version INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    encapsulated_key TEXT,
    kdf_salt TEXT,
    created_at TIMESTAMP NOT NULL
);
