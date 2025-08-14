-- MySQL-compatible auth_tokens table for integration tests
CREATE TABLE IF NOT EXISTS auth_tokens (
    token_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    access_token VARCHAR(255) NOT NULL UNIQUE,
    refresh_token VARCHAR(255),
    token_type VARCHAR(50),
    expires_at DATETIME NOT NULL,
    scopes TEXT,
    issued_at DATETIME NOT NULL,
    auth_method VARCHAR(100) NOT NULL,
    subject VARCHAR(255),
    issuer VARCHAR(255),
    client_id VARCHAR(255),
    metadata TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_auth_tokens_user_id (user_id),
    INDEX idx_auth_tokens_access_token (access_token(128)),
    INDEX idx_auth_tokens_expires_at (expires_at)
);
