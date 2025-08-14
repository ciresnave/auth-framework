-- MySQL-compatible sessions table for integration tests
CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    data TEXT,
    INDEX idx_sessions_user_id (user_id),
    INDEX idx_sessions_expires_at (expires_at)
);
