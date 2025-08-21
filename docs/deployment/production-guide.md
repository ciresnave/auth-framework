# AuthFramework v0.4.0 - Production Deployment Guide

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, or equivalent)
- **Memory**: Minimum 4GB RAM (8GB+ recommended)
- **CPU**: Minimum 2 cores (4+ cores recommended)
- **Storage**: 20GB+ available disk space
- **Network**: HTTPS-capable with valid SSL certificates

### Required Software

- Docker 20.10+
- Docker Compose v2.0+
- Git
- OpenSSL (for certificate generation)

## Quick Start (5 Minutes)

### 1. Clone Repository

```bash
git clone https://github.com/auth-framework/auth-framework.git
cd auth-framework
```

### 2. Generate Secrets

```bash
# Create secrets directory
mkdir -p secrets

# Generate secure passwords and keys
openssl rand -base64 32 > secrets/db_password.txt
openssl rand -base64 32 > secrets/redis_password.txt
openssl rand -base64 64 > secrets/jwt_secret.txt
openssl rand -base64 32 > secrets/grafana_password.txt

# Set proper permissions
chmod 600 secrets/*.txt
```

### 3. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit configuration
vim .env
```

**.env Configuration:**

```bash
# Domain configuration
DOMAIN=auth.yourdomain.com
ADMIN_EMAIL=admin@yourdomain.com

# Security settings
REQUIRE_MFA=true
SESSION_TIMEOUT=3600
RATE_LIMIT_ENABLED=true

# Performance settings
DB_MAX_CONNECTIONS=100
REDIS_MAX_MEMORY=256mb
APP_WORKER_THREADS=4

# SSL/TLS
SSL_CERT_PATH=/etc/nginx/ssl/fullchain.pem
SSL_KEY_PATH=/etc/nginx/ssl/privkey.pem
```

### 4. SSL Certificate Setup

#### Option A: Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt update && sudo apt install certbot

# Generate certificate
sudo certbot certonly --standalone \
  -d auth.yourdomain.com \
  --email admin@yourdomain.com \
  --agree-tos --non-interactive

# Copy certificates
sudo cp /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem nginx/ssl/
sudo cp /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem nginx/ssl/
sudo chown $USER:$USER nginx/ssl/*.pem
```

#### Option B: Self-Signed (Development Only)

```bash
# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/privkey.pem \
  -out nginx/ssl/fullchain.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=auth.yourdomain.com"
```

### 5. Deploy

```bash
# Production deployment
docker-compose -f docker-compose.production.yml up -d

# Verify deployment
docker-compose -f docker-compose.production.yml ps
```

### 6. Verify Installation

```bash
# Check health
curl -k https://auth.yourdomain.com/health

# Check logs
docker-compose -f docker-compose.production.yml logs -f auth-server
```

## Detailed Configuration

### Database Configuration

#### PostgreSQL Optimization

Create `postgres/postgresql.conf`:

```conf
# Memory settings
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB

# Connection settings
max_connections = 100
listen_addresses = '*'

# Performance settings
random_page_cost = 1.1
effective_io_concurrency = 200
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
```

#### Database Backup

```bash
# Automated backup script
#!/bin/bash
BACKUP_DIR="/backups/postgres"
DATE=$(date +%Y%m%d_%H%M%S)

docker exec postgres pg_dump -U auth_user auth_framework | \
  gzip > "$BACKUP_DIR/auth_framework_$DATE.sql.gz"

# Keep only last 7 days
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +7 -delete
```

### Redis Configuration

Create `redis/redis.conf`:

```conf
# Security
bind 127.0.0.1
protected-mode yes
requirepass-file /run/secrets/redis_password

# Persistence
appendonly yes
appendfsync everysec
save 900 1
save 300 10
save 60 10000

# Memory management
maxmemory 256mb
maxmemory-policy allkeys-lru

# Performance
tcp-keepalive 300
timeout 0
```

### Application Configuration

Create `config/production.toml`:

```toml
[server]
host = "0.0.0.0"
port = 8080
worker_threads = 4
max_connections = 100

[database]
url = "postgresql://auth_user@postgres:5432/auth_framework"
max_connections = 20
min_connections = 5
connect_timeout = 30

[redis]
url = "redis://redis:6379"
pool_size = 10
timeout = 5

[jwt]
algorithm = "RS256"
access_token_ttl = 3600
refresh_token_ttl = 86400
issuer = "https://auth.yourdomain.com"
audience = "authframework-api"

[security]
min_password_length = 12
require_password_complexity = true
password_hash_algorithm = "Argon2"
secure_cookies = true
csrf_protection = true
session_timeout = 3600

[rate_limiting]
enabled = true
requests_per_minute = 100
burst_size = 20

[logging]
level = "info"
format = "json"
destination = "stdout"

[monitoring]
metrics_enabled = true
metrics_path = "/metrics"
health_check_path = "/health"
```

## Security Hardening

### Firewall Configuration

```bash
# Configure UFW firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### System Security

```bash
# Disable unnecessary services
sudo systemctl disable apache2 2>/dev/null || true
sudo systemctl disable nginx 2>/dev/null || true

# Update system
sudo apt update && sudo apt upgrade -y

# Install security updates automatically
echo 'Unattended-Upgrade::Automatic-Reboot "false";' | \
  sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades
```

### Container Security

```bash
# Run Docker security benchmark
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --label docker_bench_security \
  docker/docker-bench-security
```

## Monitoring and Observability

### Grafana Dashboard Setup

1. Access Grafana: `https://auth.yourdomain.com:3000`
2. Login with admin credentials from `secrets/grafana_password.txt`
3. Import dashboards:
   - AuthFramework Application Metrics
   - Infrastructure Monitoring
   - Security Events

### Log Management

```bash
# Configure log rotation
sudo tee /etc/logrotate.d/authframework << EOF
/var/log/authframework/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
```

### Alerting Setup

```yaml
# Add to monitoring/alert_rules.yml
groups:
  - name: authframework
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: High error rate detected

      - alert: DatabaseConnectionHigh
        expr: postgres_stat_activity_count > 80
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: High database connection usage
```

## Performance Tuning

### Application Performance

```bash
# Optimize for production
export RUST_LOG=auth_framework=info
export TOKIO_WORKER_THREADS=4
export DATABASE_POOL_SIZE=20
export REDIS_POOL_SIZE=10
```

### Database Performance

```sql
-- Create optimized indexes
CREATE INDEX CONCURRENTLY idx_users_username ON users(username);
CREATE INDEX CONCURRENTLY idx_tokens_user_id ON tokens(user_id);
CREATE INDEX CONCURRENTLY idx_sessions_expires_at ON sessions(expires_at);

-- Analyze tables
ANALYZE users;
ANALYZE tokens;
ANALYZE sessions;
```

### Nginx Performance

```nginx
# Add to nginx.conf
worker_processes auto;
worker_connections 1024;
worker_rlimit_nofile 2048;

# Enable caching
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=auth_cache:10m
                 max_size=100m inactive=60m use_temp_path=off;

# In server block
proxy_cache auth_cache;
proxy_cache_valid 200 5m;
proxy_cache_valid 404 1m;
```

## Scaling and High Availability

### Horizontal Scaling

```bash
# Scale application servers
docker-compose -f docker-compose.production.yml up -d --scale auth-server=3

# Load balancer configuration update automatically
```

### Database Clustering

```yaml
# PostgreSQL cluster with replication
version: '3.8'
services:
  postgres-primary:
    image: postgres:15
    environment:
      POSTGRES_REPLICATION_MODE: master
      POSTGRES_REPLICATION_USER: replicator
      POSTGRES_REPLICATION_PASSWORD: replica_password

  postgres-replica:
    image: postgres:15
    environment:
      POSTGRES_REPLICATION_MODE: slave
      POSTGRES_MASTER_HOST: postgres-primary
      POSTGRES_REPLICATION_USER: replicator
      POSTGRES_REPLICATION_PASSWORD: replica_password
```

### Redis Clustering

```yaml
# Redis Sentinel for high availability
redis-sentinel:
  image: redis:7-alpine
  command: redis-sentinel /etc/redis/sentinel.conf
  volumes:
    - ./redis/sentinel.conf:/etc/redis/sentinel.conf
```

## Backup and Disaster Recovery

### Automated Backup Script

```bash
#!/bin/bash
# /opt/authframework/backup.sh

BACKUP_DIR="/backups/authframework"
DATE=$(date +%Y%m%d_%H%M%S)

# Database backup
docker exec postgres pg_dump -U auth_user auth_framework | \
  gzip > "$BACKUP_DIR/db_$DATE.sql.gz"

# Redis backup
docker exec redis redis-cli --rdb - | \
  gzip > "$BACKUP_DIR/redis_$DATE.rdb.gz"

# Configuration backup
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" \
  config/ secrets/ nginx/ monitoring/

# Upload to S3 (optional)
if [ "$BACKUP_TO_S3" = "true" ]; then
  aws s3 sync "$BACKUP_DIR" "s3://$S3_BACKUP_BUCKET/authframework/"
fi

# Cleanup old backups
find "$BACKUP_DIR" -type f -mtime +30 -delete
```

### Disaster Recovery Plan

1. **Service Restoration**:
   - Deploy from git repository
   - Restore database from latest backup
   - Update DNS if necessary

2. **Data Recovery**:
   - PostgreSQL point-in-time recovery
   - Redis data restoration
   - Configuration restoration

3. **Testing**:
   - Monthly disaster recovery drills
   - Backup integrity verification

## Troubleshooting

### Common Issues

#### Connection Errors

```bash
# Check container connectivity
docker network ls
docker exec auth-server ping postgres
docker exec auth-server ping redis
```

#### Performance Issues

```bash
# Monitor resource usage
docker stats
docker-compose logs auth-server | grep -i "slow\|timeout\|error"
```

#### SSL Certificate Issues

```bash
# Verify certificate
openssl x509 -in nginx/ssl/fullchain.pem -text -noout
openssl verify nginx/ssl/fullchain.pem

# Test SSL configuration
openssl s_client -connect auth.yourdomain.com:443 -servername auth.yourdomain.com
```

### Debug Mode

```bash
# Enable debug logging
docker-compose -f docker-compose.production.yml \
  exec auth-server sh -c 'RUST_LOG=debug /usr/local/bin/auth-framework-cli server'
```

## Maintenance

### Regular Maintenance Tasks

```bash
# Weekly maintenance script
#!/bin/bash

# Update containers
docker-compose -f docker-compose.production.yml pull
docker-compose -f docker-compose.production.yml up -d

# Database maintenance
docker exec postgres vacuumdb -U auth_user auth_framework
docker exec postgres reindexdb -U auth_user auth_framework

# Log rotation
docker-compose -f docker-compose.production.yml logs --no-color | \
  tail -n 10000 > /var/log/authframework/application.log

# Security updates
apt update && apt upgrade -y
```

### Certificate Renewal

```bash
# Automated Let's Encrypt renewal
0 3 * * * certbot renew --quiet && \
  cp /etc/letsencrypt/live/auth.yourdomain.com/*.pem nginx/ssl/ && \
  docker-compose -f docker-compose.production.yml restart nginx
```

## Support and Resources

### Documentation

- **API Documentation**: `/docs/api/`
- **Architecture Guide**: `/docs/architecture/`
- **Security Guide**: `/docs/security/`

### Community

- **GitHub Issues**: <https://github.com/auth-framework/auth-framework/issues>
- **Discord Community**: <https://discord.gg/authframework>
- **Stack Overflow**: Tag `authframework`

### Professional Support

- **Enterprise Support**: <enterprise@authframework.com>
- **Consulting Services**: <consulting@authframework.com>
- **Training**: <training@authframework.com>

---

**Deployment Status**: Production Ready ✅
**Last Updated**: January 2024
**Version**: 0.4.0
