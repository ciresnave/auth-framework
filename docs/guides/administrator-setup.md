# Administrator Setup Guide

## Introduction

This guide provides system administrators with comprehensive instructions for deploying, configuring, and managing AuthFramework in production environments. AuthFramework is designed to be a secure, scalable, and maintainable authentication and authorization solution.

## Production Deployment

### System Requirements

**Minimum Requirements:**

- **CPU**: 2 vCPUs
- **Memory**: 4GB RAM
- **Storage**: 20GB SSD
- **Network**: 1Gbps connection
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)

**Recommended Requirements:**

- **CPU**: 4+ vCPUs
- **Memory**: 8GB+ RAM
- **Storage**: 50GB+ SSD with RAID 1
- **Network**: 10Gbps connection
- **OS**: Ubuntu 22.04 LTS or RHEL 9

**High Availability Requirements:**

- **Load Balancer**: HAProxy, Nginx, or cloud load balancer
- **Database**: PostgreSQL cluster with replication
- **Cache**: Redis cluster with failover
- **Storage**: Distributed storage with redundancy

### Installation Methods

#### Docker Deployment (Recommended)

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  auth-framework:
    image: authframework/auth-framework:0.4.0
    ports:
      - "8080:8080"
      - "8443:8443"
    environment:
      - AUTH_CONFIG_FILE=/app/config/auth-config.toml
      - DATABASE_URL=postgresql://auth_user:${DB_PASSWORD}@postgres:5432/authframework
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=${JWT_SECRET}
    volumes:
      - ./config:/app/config
      - ./certs:/app/certs
      - ./logs:/app/logs
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=authframework
      - POSTGRES_USER=auth_user
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./sql/init.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U auth_user -d authframework"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    depends_on:
      - auth-framework
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

#### Kubernetes Deployment

Create Kubernetes manifests:

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: auth-framework

---
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-config
  namespace: auth-framework
data:
  auth-config.toml: |
    [server]
    host = "0.0.0.0"
    port = 8080
    tls_port = 8443

    [security]
    require_https = true
    jwt_expiry = "1h"

    [storage]
    type = "postgresql"

    [logging]
    level = "info"
    format = "json"

---
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-secrets
  namespace: auth-framework
type: Opaque
stringData:
  JWT_SECRET: "your-jwt-secret-here"
  DATABASE_URL: "postgresql://auth_user:password@postgres:5432/authframework"
  REDIS_URL: "redis://redis:6379"

---
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-framework
  namespace: auth-framework
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-framework
  template:
    metadata:
      labels:
        app: auth-framework
    spec:
      containers:
      - name: auth-framework
        image: authframework/auth-framework:0.4.0
        ports:
        - containerPort: 8080
        - containerPort: 8443
        env:
        - name: AUTH_CONFIG_FILE
          value: "/app/config/auth-config.toml"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: DATABASE_URL
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: JWT_SECRET
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: certs
          mountPath: /app/certs
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: auth-config
      - name: certs
        secret:
          secretName: tls-certs

---
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-framework
  namespace: auth-framework
spec:
  selector:
    app: auth-framework
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: https
    port: 443
    targetPort: 8443
  type: ClusterIP

---
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-framework
  namespace: auth-framework
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - auth.yourdomain.com
    secretName: auth-tls
  rules:
  - host: auth.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-framework
            port:
              number: 80
```

### Configuration Management

#### Production Configuration File

Create `/app/config/auth-config.toml`:

```toml
[server]
host = "0.0.0.0"
port = 8080
tls_port = 8443
max_connections = 1000
request_timeout = "30s"
keepalive_timeout = "75s"

[security]
jwt_secret = "${JWT_SECRET}"
jwt_expiry = "15m"
refresh_token_expiry = "7d"
require_https = true
require_mfa = false
password_policy = "strong"
session_timeout = "24h"
max_login_attempts = 5
lockout_duration = "15m"

[storage]
type = "postgresql"
url = "${DATABASE_URL}"
max_connections = 20
min_connections = 5
connection_timeout = "30s"
idle_timeout = "10m"

[cache]
type = "redis"
url = "${REDIS_URL}"
default_ttl = "5m"
max_memory_mb = 256

[rate_limiting]
enabled = true
requests_per_minute = 60
burst_limit = 10
cleanup_interval = "1m"

[logging]
level = "info"
format = "json"
output = "stdout"
log_requests = true
log_security_events = true

[monitoring]
enabled = true
metrics_port = 9090
health_check_path = "/health"
ready_check_path = "/ready"

[cors]
enabled = true
allowed_origins = ["https://yourapp.com"]
allowed_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
allowed_headers = ["Authorization", "Content-Type"]
max_age = 3600

[tls]
cert_file = "/app/certs/server.crt"
key_file = "/app/certs/server.key"
protocols = ["TLSv1.2", "TLSv1.3"]
cipher_suites = "secure"
```

#### Environment Variables

Set environment variables for sensitive configuration:

```bash
# Database configuration
export DATABASE_URL="postgresql://auth_user:secure_password@localhost:5432/authframework?sslmode=require"

# Redis configuration
export REDIS_URL="redis://:redis_password@localhost:6379"

# JWT configuration
export JWT_SECRET="your-256-bit-secret-key-here"

# Optional: Additional security
export ENCRYPTION_KEY="your-encryption-key-for-sensitive-data"
export API_KEY_SECRET="secret-for-api-key-generation"
```

### Database Setup

#### PostgreSQL Installation and Configuration

Install PostgreSQL:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql postgresql-contrib

# CentOS/RHEL
sudo dnf install postgresql postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

Configure PostgreSQL:

```sql
-- Create database and user
CREATE DATABASE authframework;
CREATE USER auth_user WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE authframework TO auth_user;

-- Connect to authframework database
\c authframework

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO auth_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO auth_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO auth_user;
```

Configure PostgreSQL settings in `/etc/postgresql/*/main/postgresql.conf`:

```conf
# Connection settings
listen_addresses = 'localhost'
port = 5432
max_connections = 100

# Memory settings
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB

# WAL settings
wal_level = replica
max_wal_size = 1GB
min_wal_size = 80MB

# Logging
log_statement = 'mod'
log_min_duration_statement = 1000
log_connections = on
log_disconnections = on

# Security
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'
```

#### Redis Installation and Configuration

Install Redis:

```bash
# Ubuntu/Debian
sudo apt install redis-server

# CentOS/RHEL
sudo dnf install redis
sudo systemctl enable redis
sudo systemctl start redis
```

Configure Redis in `/etc/redis/redis.conf`:

```conf
# Basic configuration
bind 127.0.0.1
port 6379
requirepass your_redis_password

# Memory management
maxmemory 256mb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000

# Security
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log
```

### SSL/TLS Configuration

#### Generate SSL Certificates

Using Let's Encrypt (recommended):

```bash
# Install certbot
sudo apt install certbot

# Generate certificate
sudo certbot certonly --standalone -d auth.yourdomain.com

# Certificates will be in /etc/letsencrypt/live/auth.yourdomain.com/
```

Using self-signed certificates (development only):

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate certificate signing request
openssl req -new -key server.key -out server.csr

# Generate self-signed certificate
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

# Set proper permissions
chmod 600 server.key
chmod 644 server.crt
```

#### Nginx SSL Configuration

Configure Nginx as reverse proxy:

```nginx
# /etc/nginx/sites-available/auth-framework
upstream auth_backend {
    server 127.0.0.1:8080;
    server 127.0.0.1:8081;  # If running multiple instances
    keepalive 32;
}

server {
    listen 80;
    server_name auth.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";

    # Proxy configuration
    location / {
        proxy_pass http://auth_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 86400;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://auth_backend/health;
        access_log off;
    }

    # Metrics endpoint (restrict access)
    location /metrics {
        proxy_pass http://auth_backend/metrics;
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
    }
}
```

### Monitoring and Logging

#### Prometheus Monitoring

Configure Prometheus to scrape AuthFramework metrics:

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'auth-framework'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 5s
    metrics_path: /metrics
```

#### Grafana Dashboard

Import the AuthFramework Grafana dashboard:

```json
{
  "dashboard": {
    "title": "AuthFramework Monitoring",
    "panels": [
      {
        "title": "Authentication Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(auth_attempts_total[5m])",
            "legendFormat": "{{status}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(auth_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      }
    ]
  }
}
```

#### Log Aggregation

Configure log aggregation with ELK stack:

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /app/logs/*.log
  fields:
    service: auth-framework
  fields_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "auth-framework-%{+yyyy.MM.dd}"

setup.template.name: "auth-framework"
setup.template.pattern: "auth-framework-*"
```

### Backup and Recovery

#### Database Backup

Create automated PostgreSQL backups:

```bash
#!/bin/bash
# /usr/local/bin/backup-auth-db.sh

BACKUP_DIR="/backups/postgresql"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="authframework"
DB_USER="auth_user"

# Create backup directory
mkdir -p $BACKUP_DIR

# Create database dump
pg_dump -U $DB_USER -h localhost $DB_NAME | gzip > $BACKUP_DIR/auth_backup_$DATE.sql.gz

# Remove backups older than 30 days
find $BACKUP_DIR -name "auth_backup_*.sql.gz" -mtime +30 -delete

# Upload to S3 (optional)
aws s3 cp $BACKUP_DIR/auth_backup_$DATE.sql.gz s3://your-backup-bucket/postgresql/
```

Add to crontab:

```bash
# Run daily at 2 AM
0 2 * * * /usr/local/bin/backup-auth-db.sh
```

#### Redis Backup

Configure Redis persistence and backup:

```bash
#!/bin/bash
# /usr/local/bin/backup-redis.sh

BACKUP_DIR="/backups/redis"
DATE=$(date +%Y%m%d_%H%M%S)
REDIS_DATA="/var/lib/redis"

# Create backup directory
mkdir -p $BACKUP_DIR

# Save current Redis state
redis-cli BGSAVE

# Wait for background save to complete
while [ $(redis-cli LASTSAVE) -eq $(redis-cli LASTSAVE) ]; do
  sleep 1
done

# Copy dump file
cp $REDIS_DATA/dump.rdb $BACKUP_DIR/redis_backup_$DATE.rdb

# Compress backup
gzip $BACKUP_DIR/redis_backup_$DATE.rdb

# Remove old backups
find $BACKUP_DIR -name "redis_backup_*.rdb.gz" -mtime +7 -delete
```

### Security Hardening

#### System Security

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Configure firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups
sudo systemctl disable avahi-daemon

# Configure fail2ban
sudo apt install fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Edit /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
```

#### Application Security

```bash
# Run as non-root user
sudo useradd -r -s /bin/false authframework
sudo chown -R authframework:authframework /app

# Set file permissions
chmod 755 /app
chmod 644 /app/config/*
chmod 600 /app/config/secrets.env
chmod 644 /app/certs/*.crt
chmod 600 /app/certs/*.key

# Configure systemd service
sudo tee /etc/systemd/system/auth-framework.service << EOF
[Unit]
Description=AuthFramework Authentication Service
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=authframework
Group=authframework
WorkingDirectory=/app
ExecStart=/app/bin/auth-framework
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/app/logs /app/data

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable auth-framework
sudo systemctl start auth-framework
```

### Operations and Maintenance

#### Health Checks

Configure comprehensive health checks:

```bash
#!/bin/bash
# /usr/local/bin/health-check.sh

# Check service status
if ! systemctl is-active --quiet auth-framework; then
    echo "CRITICAL: AuthFramework service is not running"
    exit 2
fi

# Check HTTP endpoint
if ! curl -sf http://localhost:8080/health > /dev/null; then
    echo "CRITICAL: AuthFramework health endpoint not responding"
    exit 2
fi

# Check database connectivity
if ! pg_isready -h localhost -p 5432 -U auth_user > /dev/null; then
    echo "WARNING: PostgreSQL not accessible"
    exit 1
fi

# Check Redis connectivity
if ! redis-cli ping > /dev/null; then
    echo "WARNING: Redis not accessible"
    exit 1
fi

echo "OK: All services healthy"
exit 0
```

#### Log Rotation

Configure log rotation:

```bash
# /etc/logrotate.d/auth-framework
/app/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    postrotate
        systemctl reload auth-framework
    endscript
}
```

#### Performance Tuning

System-level optimizations:

```bash
# /etc/sysctl.d/99-auth-framework.conf
# Network optimizations
net.core.somaxconn = 1024
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 1024

# Memory optimizations
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# File descriptor limits
fs.file-max = 65536
```

User limits in `/etc/security/limits.conf`:

```conf
authframework soft nofile 65536
authframework hard nofile 65536
authframework soft nproc 32768
authframework hard nproc 32768
```

## Troubleshooting

### Common Issues

**Issue: Service fails to start**

```bash
# Check service status
sudo systemctl status auth-framework

# Check logs
sudo journalctl -u auth-framework -f

# Verify configuration
auth-framework --config /app/config/auth-config.toml --validate
```

**Issue: Database connection failures**

```bash
# Test database connection
psql -h localhost -U auth_user -d authframework -c "SELECT 1;"

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

**Issue: High memory usage**

```bash
# Monitor memory usage
top -p $(pgrep auth-framework)

# Check for memory leaks
valgrind --leak-check=full /app/bin/auth-framework
```

### Performance Monitoring

Monitor key performance metrics:

- **Authentication Rate**: Requests per second
- **Response Time**: 95th percentile latency
- **Error Rate**: Failed authentication percentage
- **Resource Usage**: CPU, memory, disk I/O
- **Database Performance**: Query time, connection pool usage
- **Cache Hit Rate**: Redis cache effectiveness

## Support and Resources

- **Documentation**: [docs.authframework.dev](https://docs.authframework.dev)
- **GitHub**: [github.com/authframework/auth-framework](https://github.com/authframework/auth-framework)
- **Community**: [Discord](https://discord.gg/authframework)
- **Enterprise Support**: [enterprise@authframework.dev](mailto:enterprise@authframework.dev)

---

*AuthFramework v0.4.0 - THE premier authentication and authorization solution*
