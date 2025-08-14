-- MySQL-compatible kv_store table for integration tests
CREATE TABLE IF NOT EXISTS kv_store (
    `key` VARCHAR(255) PRIMARY KEY,
    `value` BLOB
);
