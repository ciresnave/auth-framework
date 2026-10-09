# Docker Deployment Guide

Complete guide for deploying AuthFramework with Docker, featuring PostgreSQL as the recommended database backend.

## Quick Start with Docker Compose

The fastest way to get AuthFramework running with PostgreSQL:

```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: authframework
      POSTGRES_USER: authuser
      POSTGRES_PASSWORD: ${DB_PASSWORD:-secure_password_123}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init-db.sql:/docker-entrypoint-initdb.d/init-db.sql
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authuser -d authframework"]
      interval: 10s
      timeout: 5s
      retries: 5

  authframework:
    image: authframework/server:latest
    environment:
      # Database Configuration (PostgreSQL recommended)
      DATABASE_URL: postgresql://authuser:${DB_PASSWORD:-secure_password_123}@postgres:5432/authframework
      
      # Server Configuration
      AUTH_API_HOST: 0.0.0.0
      AUTH_API_PORT: 8080
      
      # JWT Configuration
      JWT_SECRET: ${JWT_SECRET:-your-super-secret-jwt-key-change-this-in-production}
      JWT_ALGORITHM: HS256
      JWT_EXPIRATION: 3600
      
      # Security Configuration
      # Configure CORS through the mounted application config file or your own
      # entrypoint wrapper; AuthFramework does not provide a built-in
      # CORS environment-variable loader for ApiServerConfig.
      RATE_LIMIT_REQUESTS_PER_MINUTE: 100
      
      # Logging
      RUST_LOG: info
    ports:
      - "8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./config:/app/config:ro
    restart: unless-stopped

volumes:
  postgres_data:
```

### Environment Variables

Create a `.env` file:

```bash
# .env
DB_PASSWORD=your_secure_database_password
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters-long
DATABASE_URL=postgresql://auth_user:${DB_PASSWORD}@postgres:5432/auth_framework
JWT_ISSUER=auth-framework
JWT_AUDIENCE=api
```

### Database Initialization

Create `init-db.sql` for database setup:

```sql
-- init-db.sql
-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create indexes for performance
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tokens_user_id ON auth_tokens(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at);

-- Create optimized sequences
CREATE SEQUENCE IF NOT EXISTS users_id_seq;
CREATE SEQUENCE IF NOT EXISTS roles_id_seq;
CREATE SEQUENCE IF NOT EXISTS permissions_id_seq;
```

### Launch Commands

```bash
# Start the complete stack
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f authframework

# Stop the stack
docker-compose down

# Stop and remove data (⚠️ destructive)
docker-compose down -v
```

## Production Docker Configuration

### Multi-Stage Dockerfile

```dockerfile
# Dockerfile
# Build stage
FROM rust:1.95-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    postgresql-dev \
    openssl-dev \
    pkgconfig

WORKDIR /app

# Copy dependency files
COPY Cargo.toml Cargo.lock ./

# Create dummy main to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --features api-server,postgres-storage
RUN rm -rf src

# Copy source code
COPY src ./src
COPY examples ./examples

# Build the application
RUN cargo build --release --features api-server,postgres-storage --bin auth-framework

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    libssl3 \
    postgresql-client

# Create app user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Copy binary from builder
COPY --from=builder /app/target/release/auth-framework /usr/local/bin/auth-framework

# Create directories
RUN mkdir -p /app/config /app/logs && \
    chown -R appuser:appgroup /app

# Switch to app user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:${AUTH_API_PORT:-8080}/health || exit 1

EXPOSE 8080

CMD ["auth-framework", "--config", "/app/config/auth.toml"]
```

### Production Docker Compose

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: authframework
      POSTGRES_USER: authuser
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./postgresql.conf:/etc/postgresql/postgresql.conf
    command: postgres -c config_file=/etc/postgresql/postgresql.conf
    ports:
      - "127.0.0.1:5432:5432"
    secrets:
      - db_password
    deploy:
      resources:
        limits:
          memory: 1G
        reservations:
          memory: 512M
    restart: unless-stopped

  authframework:
    image: authframework/server:latest
    environment:
      DATABASE_URL_FILE: /run/secrets/database_url
      JWT_SECRET_FILE: /run/secrets/jwt_secret
      AUTH_API_HOST: 0.0.0.0
      AUTH_API_PORT: 8080
      RUST_LOG: warn
    ports:
      - "127.0.0.1:8080:8080"
    secrets:
      - database_url
      - jwt_secret
    volumes:
      - ./config/prod:/app/config:ro
      - logs:/app/logs
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
    depends_on:
      - postgres

  # Reverse proxy (optional)
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
      - nginx_logs:/var/log/nginx
    depends_on:
      - authframework

secrets:
  db_password:
    external: true
  database_url:
    external: true
  jwt_secret:
    external: true

volumes:
  postgres_data:
  logs:
  nginx_logs:
```

## Kubernetes Deployment

### Deployment Manifest

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authframework
  labels:
    app: authframework
spec:
  replicas: 3
  selector:
    matchLabels:
      app: authframework
  template:
    metadata:
      labels:
        app: authframework
    spec:
      containers:
      - name: authframework
        image: authframework/server:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: authframework-secrets
              key: database-url
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: authframework-secrets
              key: jwt-secret
        - name: AUTH_API_HOST
          value: "0.0.0.0"
        - name: AUTH_API_PORT
          value: "8080"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: authframework-service
spec:
  selector:
    app: authframework
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: LoadBalancer

---
apiVersion: v1
kind: Secret
metadata:
  name: authframework-secrets
type: Opaque
data:
  database-url: <base64-encoded-database-url>
  jwt-secret: <base64-encoded-jwt-secret>
```

## Performance Optimization

### PostgreSQL Tuning

```conf
# postgresql.conf
# Memory settings
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
work_mem = 4MB

# Connection settings
max_connections = 100
shared_preload_libraries = 'pg_stat_statements'

# Performance settings
random_page_cost = 1.1
effective_io_concurrency = 200
max_worker_processes = 4
max_parallel_workers_per_gather = 2
max_parallel_workers = 4

# WAL settings
wal_level = replica
max_wal_size = 1GB
min_wal_size = 80MB
checkpoint_completion_target = 0.9

# Logging
log_statement = 'none'
log_line_prefix = '%t [%p-%l] %q%u@%d '
log_checkpoints = on
log_lock_waits = on
log_temp_files = 0
```

### Resource Monitoring

```yaml
# monitoring.yml - Add to docker-compose
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  grafana_data:
```

## Security Best Practices

### Network Security

```yaml
# Use custom networks
networks:
  authnet:
    driver: bridge
    internal: true
  webnet:
    driver: bridge

services:
  postgres:
    networks:
      - authnet  # Only internal access
  
  authframework:
    networks:
      - authnet  # Database access
      - webnet   # External access
```

### Secret Management

```bash
# Using Docker secrets
echo "super_secure_password" | docker secret create db_password -
echo "jwt-secret-key-32-chars-minimum" | docker secret create jwt_secret -

# Using environment files
docker-compose --env-file .env.prod up -d
```

### SSL/TLS Configuration

```nginx
# nginx.conf
server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    
    location / {
        proxy_pass http://authframework:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Backup and Recovery

### Automated PostgreSQL Backups

```bash
#!/bin/bash
# backup.sh
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="authframework_backup_${DATE}.sql"

docker exec postgres pg_dump -U authuser -d authframework > "${BACKUP_DIR}/${BACKUP_FILE}"
gzip "${BACKUP_DIR}/${BACKUP_FILE}"

# Keep only last 7 days of backups
find ${BACKUP_DIR} -name "authframework_backup_*.sql.gz" -mtime +7 -delete
```

### Recovery Process

```bash
# Restore from backup
gunzip -c /backups/authframework_backup_20250930_120000.sql.gz | \
  docker exec -i postgres psql -U authuser -d authframework
```

## Troubleshooting

### Common Issues

**Database Connection Failures:**

```bash
# Check PostgreSQL status
docker-compose logs postgres

# Test connection
docker exec -it postgres psql -U authuser -d authframework
```

**Performance Issues:**

```bash
# Monitor resource usage
docker stats

# Check slow queries
docker exec -it postgres psql -U authuser -d authframework \
  -c "SELECT * FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"
```

**Container Crashes:**

```bash
# Check container logs
docker-compose logs --tail=100 authframework

# Inspect container
docker inspect authframework_authframework_1
```

### Debug Mode

```yaml
# docker-compose.debug.yml
services:
  authframework:
    environment:
      RUST_LOG: debug
      RUST_BACKTRACE: 1
    volumes:
      - ./debug:/app/debug
```

## Scaling Strategies

### Horizontal Scaling

```yaml
# docker-compose.scale.yml
services:
  authframework:
    deploy:
      replicas: 3
    environment:
      - INSTANCE_ID={{.Task.Slot}}
```

### Load Balancing

```yaml
services:
  haproxy:
    image: haproxy:alpine
    ports:
      - "80:80"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    depends_on:
      - authframework
```

This Docker deployment guide provides production-ready configurations with PostgreSQL as the recommended database, emphasizing security, performance, and operational excellence.
