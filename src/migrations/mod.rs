//! Database migration system for auth-framework.
//! This module provides tools for managing database schema changes
//! and ensuring proper setup of authentication-related tables.
#[cfg(feature = "mysql-storage")]
use sqlx::MySqlPool;

#[cfg(feature = "mysql-storage")]
pub struct MySqlMigrationManager {
    pool: MySqlPool,
}

#[cfg(feature = "mysql-storage")]
impl MySqlMigrationManager {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    /// Run all pending migrations (stub)
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        // Example: create users table if not exists
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(36) PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )"#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(any(feature = "cli", feature = "postgres-storage"))]
use tokio_postgres::{Client, Error as PgError};

/// Migration manager for database schema changes
#[cfg(any(feature = "cli", feature = "postgres-storage"))]
pub struct MigrationManager {
    client: Client,
}

#[cfg(any(feature = "cli", feature = "postgres-storage"))]
#[derive(Debug, Clone)]
pub struct Migration {
    pub version: i64,
    pub name: String,
    pub sql: String,
}

#[cfg(any(feature = "cli", feature = "postgres-storage"))]
impl MigrationManager {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Run all pending migrations
    pub async fn migrate(&mut self) -> Result<(), MigrationError> {
        // Ensure migrations table exists
        self.ensure_migrations_table().await?;

        let applied = self.get_applied_migrations().await?;
        let available = self.get_available_migrations();

        for migration in available {
            if !applied.contains(&migration.version) {
                println!("Applying migration: {}", migration.name);
                self.apply_migration(&migration).await?;
            }
        }

        Ok(())
    }

    async fn ensure_migrations_table(&self) -> Result<(), PgError> {
        self.client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS _auth_migrations (
                version BIGINT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
            "#,
                &[],
            )
            .await?;
        Ok(())
    }

    async fn get_applied_migrations(&self) -> Result<Vec<i64>, PgError> {
        let rows = self
            .client
            .query("SELECT version FROM _auth_migrations ORDER BY version", &[])
            .await?;

        Ok(rows.iter().map(|row| row.get(0)).collect())
    }

    fn get_available_migrations(&self) -> Vec<Migration> {
        vec![
            Migration {
                version: 1,
                name: "create_users_table".to_string(),
                sql: r#"
                    CREATE TABLE IF NOT EXISTS users (
                        id VARCHAR(36) PRIMARY KEY,
                        username VARCHAR(255) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        email VARCHAR(255) UNIQUE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                        is_active BOOLEAN DEFAULT true,
                        last_login TIMESTAMP WITH TIME ZONE
                    );
                    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                "#.to_string(),
            },
            Migration {
                version: 2,
                name: "create_roles_permissions".to_string(),
                sql: r#"
                    CREATE TABLE IF NOT EXISTS roles (
                        id VARCHAR(36) PRIMARY KEY,
                        name VARCHAR(100) UNIQUE NOT NULL,
                        description TEXT,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    );

                    CREATE TABLE IF NOT EXISTS permissions (
                        id VARCHAR(36) PRIMARY KEY,
                        action VARCHAR(100) NOT NULL,
                        resource VARCHAR(100) NOT NULL,
                        instance VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    );

                    CREATE TABLE IF NOT EXISTS user_roles (
                        user_id VARCHAR(36) REFERENCES users(id),
                        role_id VARCHAR(36) REFERENCES roles(id),
                        PRIMARY KEY (user_id, role_id)
                    );

                    CREATE TABLE IF NOT EXISTS role_permissions (
                        role_id VARCHAR(36) REFERENCES roles(id),
                        permission_id VARCHAR(36) REFERENCES permissions(id),
                        PRIMARY KEY (role_id, permission_id)
                    );
                "#.to_string(),
            },
            Migration {
                version: 3,
                name: "create_sessions_table".to_string(),
                sql: r#"
                    CREATE TABLE IF NOT EXISTS sessions (
                        id VARCHAR(36) PRIMARY KEY,
                        user_id VARCHAR(36) REFERENCES users(id),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                        last_accessed TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        state VARCHAR(20) DEFAULT 'active',
                        device_fingerprint TEXT,
                        ip_address INET,
                        user_agent TEXT,
                        security_flags TEXT[]
                    );
                    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
                    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
                "#.to_string(),
            },
            Migration {
                version: 4,
                name: "create_audit_logs".to_string(),
                sql: r#"
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id VARCHAR(36) PRIMARY KEY,
                        event_type VARCHAR(50) NOT NULL,
                        timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                        user_id VARCHAR(36),
                        session_id VARCHAR(36),
                        resource VARCHAR(100),
                        action VARCHAR(100),
                        success BOOLEAN NOT NULL,
                        ip_address INET,
                        user_agent TEXT,
                        details JSONB
                    );
                    CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
                    CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
                "#.to_string(),
            },
            Migration {
                version: 5,
                name: "create_mfa_table".to_string(),
                sql: r#"
                    CREATE TABLE IF NOT EXISTS mfa_secrets (
                        user_id VARCHAR(36) PRIMARY KEY REFERENCES users(id),
                        totp_secret VARCHAR(255),
                        backup_codes TEXT[],
                        phone_number VARCHAR(20),
                        email_verified BOOLEAN DEFAULT false,
                        phone_verified BOOLEAN DEFAULT false,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    );

                    CREATE TABLE IF NOT EXISTS mfa_challenges (
                        id VARCHAR(36) PRIMARY KEY,
                        user_id VARCHAR(36) REFERENCES users(id),
                        challenge_type VARCHAR(20) NOT NULL,
                        challenge_data TEXT,
                        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    );
                    CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires_at ON mfa_challenges(expires_at);
                "#.to_string(),
            },
        ]
    }

    async fn apply_migration(&mut self, migration: &Migration) -> Result<(), MigrationError> {
        let tx = self.client.transaction().await?;

        // Execute migration SQL
        tx.batch_execute(&migration.sql).await?;

        // Record migration
        use tokio_postgres::types::ToSql;
        tx.execute(
            "INSERT INTO _auth_migrations (version, name) VALUES ($1, $2)",
            &[
                &migration.version as &(dyn ToSql + Sync),
                &migration.name.as_str() as &(dyn ToSql + Sync),
            ],
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Check migration status
    pub async fn status(&self) -> Result<MigrationStatus, MigrationError> {
        let applied = self
            .get_applied_migrations()
            .await
            .map_err(MigrationError::Database)?;
        let available = self.get_available_migrations();

        let pending: Vec<_> = available
            .iter()
            .filter(|m| !applied.contains(&m.version))
            .collect();

        Ok(MigrationStatus {
            applied_count: applied.len(),
            pending_count: pending.len(),
            latest_applied: applied.last().copied(),
            next_pending: pending.first().map(|m| m.version),
        })
    }

    /// Create a new migration (for external use)
    pub fn create_migration(version: i64, name: String, sql: String) -> Migration {
        Migration { version, name, sql }
    }

    /// Get list of available migrations
    pub fn list_available_migrations(&self) -> Vec<Migration> {
        // Return cloned migrations to avoid lifetime issues
        self.get_available_migrations()
    }
}

#[derive(Debug)]
pub struct MigrationStatus {
    pub applied_count: usize,
    pub pending_count: usize,
    pub latest_applied: Option<i64>,
    pub next_pending: Option<i64>,
}

#[cfg(any(feature = "cli", feature = "postgres-storage"))]
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("Database error: {0}")]
    Database(PgError),
    #[error("Migration not found: {0}")]
    NotFound(i64),
    #[error("Invalid migration order")]
    InvalidOrder,
}

#[cfg(any(feature = "cli", feature = "postgres-storage"))]
impl From<PgError> for MigrationError {
    fn from(e: PgError) -> Self {
        MigrationError::Database(e)
    }
}

#[cfg(any(feature = "cli", feature = "postgres-storage"))]
/// CLI tool for running migrations
pub struct MigrationCli;

#[cfg(any(feature = "cli", feature = "postgres-storage"))]
impl MigrationCli {
    pub async fn run(database_url: &str, command: &str) -> Result<(), Box<dyn std::error::Error>> {
        let (client, connection) =
            tokio_postgres::connect(database_url, tokio_postgres::NoTls).await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Connection error: {}", e);
            }
        });
        let mut manager = MigrationManager::new(client);

        match command {
            "migrate" => {
                manager.migrate().await?;
                println!("Migrations completed successfully");
            }
            "status" => {
                let status = manager.status().await?;
                println!("Migration Status:");
                println!("  Applied: {}", status.applied_count);
                println!("  Pending: {}", status.pending_count);
                if let Some(latest) = status.latest_applied {
                    println!("  Latest Applied: {}", latest);
                }
                if let Some(next) = status.next_pending {
                    println!("  Next Pending: {}", next);
                }
            }
            _ => {
                eprintln!("Unknown command: {}", command);
                eprintln!("Available commands: migrate, status");
            }
        }

        Ok(())
    }
}


