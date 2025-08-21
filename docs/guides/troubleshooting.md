# Troubleshooting Guide

## Introduction

This guide provides comprehensive troubleshooting procedures for common issues encountered when deploying, configuring, and operating AuthFramework. It includes diagnostic techniques, resolution steps, and preventive measures to maintain a healthy authentication system.

## Quick Diagnostic Steps

### System Health Check

Run these commands to quickly assess system health:

```bash
# Check AuthFramework service status
systemctl status auth-framework

# Verify process is running
ps aux | grep auth-framework

# Check listening ports
netstat -tlnp | grep :8080

# Test health endpoint
curl -f http://localhost:8080/health || echo "Health check failed"

# Check disk space
df -h

# Check memory usage
free -h

# Check recent logs
journalctl -u auth-framework --since "10 minutes ago"
```

### Configuration Validation

Validate your configuration before troubleshooting:

```bash
# Validate configuration file
auth-framework --config /app/config/auth-config.toml --validate

# Check environment variables
env | grep -E "(JWT_SECRET|DATABASE_URL|REDIS_URL)"

# Test database connection
psql -h localhost -U auth_user -d authframework -c "SELECT 1;"

# Test Redis connection
redis-cli ping

# Verify SSL certificates
openssl x509 -in /app/certs/server.crt -text -noout
```

## Common Issues and Solutions

### Service Startup Issues

#### Issue: Service Fails to Start

**Symptoms:**

- `systemctl start auth-framework` fails
- No process running on expected ports
- Error messages in system logs

**Diagnostic Steps:**

```bash
# Check service status and logs
systemctl status auth-framework -l
journalctl -u auth-framework --since "1 hour ago"

# Check configuration syntax
auth-framework --config /app/config/auth-config.toml --validate

# Verify file permissions
ls -la /app/config/
ls -la /app/certs/

# Check port availability
netstat -tlnp | grep :8080
```

**Common Causes and Solutions:**

1. **Configuration Error**

   ```bash
   # Check for syntax errors
   auth-framework --config /app/config/auth-config.toml --validate

   # Common fixes:
   # - Fix TOML syntax errors
   # - Verify environment variable substitution
   # - Check file paths exist
   ```

2. **Permission Issues**

   ```bash
   # Fix file permissions
   sudo chown -R authframework:authframework /app
   chmod 755 /app
   chmod 644 /app/config/*.toml
   chmod 600 /app/config/secrets.env
   chmod 600 /app/certs/*.key
   chmod 644 /app/certs/*.crt
   ```

3. **Port Already in Use**

   ```bash
   # Find process using port
   lsof -i :8080

   # Kill conflicting process or change port
   sudo kill -9 <PID>
   # or modify port in configuration
   ```

4. **Missing Dependencies**

   ```bash
   # Install required packages
   sudo apt update
   sudo apt install postgresql-client redis-tools curl
   ```

#### Issue: Service Starts But Becomes Unresponsive

**Symptoms:**

- Process exists but doesn't respond to requests
- Health check endpoints timeout
- High CPU or memory usage

**Diagnostic Steps:**

```bash
# Check resource usage
top -p $(pgrep auth-framework)
htop -p $(pgrep auth-framework)

# Check file descriptors
ls /proc/$(pgrep auth-framework)/fd | wc -l
cat /proc/$(pgrep auth-framework)/limits | grep "Max open files"

# Check network connections
netstat -an | grep $(pgrep auth-framework)

# Generate stack trace (if compiled with debug symbols)
gdb -p $(pgrep auth-framework) --batch --ex "thread apply all bt" --ex "quit"
```

**Solutions:**

1. **Memory Leak**

   ```bash
   # Monitor memory usage over time
   while true; do
     ps -p $(pgrep auth-framework) -o pid,vsz,rss,pmem,time
     sleep 60
   done

   # Restart service and monitor
   systemctl restart auth-framework
   ```

2. **File Descriptor Exhaustion**

   ```bash
   # Increase limits in /etc/security/limits.conf
   authframework soft nofile 65536
   authframework hard nofile 65536

   # Restart service
   systemctl restart auth-framework
   ```

3. **Database Connection Pool Exhaustion**

   ```toml
   # Adjust in auth-config.toml
   [storage]
   max_connections = 10  # Reduce if database is overloaded
   connection_timeout = "60s"  # Increase timeout
   ```

### Database Connection Issues

#### Issue: Cannot Connect to Database

**Symptoms:**

- "Connection refused" errors
- Database timeout errors
- Service fails to start with database errors

**Diagnostic Steps:**

```bash
# Test database connectivity
pg_isready -h localhost -p 5432 -U auth_user

# Test authentication
psql -h localhost -U auth_user -d authframework -c "SELECT version();"

# Check PostgreSQL service
systemctl status postgresql

# Check PostgreSQL logs
tail -f /var/log/postgresql/postgresql-*.log

# Check network connectivity
telnet localhost 5432
```

**Solutions:**

1. **PostgreSQL Not Running**

   ```bash
   # Start PostgreSQL
   sudo systemctl start postgresql
   sudo systemctl enable postgresql

   # Check status
   sudo systemctl status postgresql
   ```

2. **Authentication Failure**

   ```bash
   # Reset user password
   sudo -u postgres psql -c "ALTER USER auth_user PASSWORD 'new_password';"

   # Update connection string
   export DATABASE_URL="postgresql://auth_user:new_password@localhost:5432/authframework"
   ```

3. **Connection Limit Exceeded**

   ```sql
   -- Check current connections
   SELECT count(*) FROM pg_stat_activity WHERE usename = 'auth_user';

   -- Check connection limit
   SELECT setting FROM pg_settings WHERE name = 'max_connections';

   -- Increase limit in postgresql.conf
   max_connections = 200
   ```

4. **Network Configuration**

   ```bash
   # Check PostgreSQL listen addresses
   grep listen_addresses /etc/postgresql/*/main/postgresql.conf

   # Check pg_hba.conf for authentication rules
   grep auth_user /etc/postgresql/*/main/pg_hba.conf
   ```

#### Issue: Slow Database Queries

**Symptoms:**

- High response times
- Database query timeouts
- Poor application performance

**Diagnostic Steps:**

```sql
-- Check slow queries
SELECT query, mean_exec_time, calls, total_exec_time
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;

-- Check active queries
SELECT pid, now() - pg_stat_activity.query_start AS duration, query
FROM pg_stat_activity
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';

-- Check database size
SELECT pg_size_pretty(pg_database_size('authframework'));

-- Check table sizes
SELECT schemaname,tablename,attname,n_distinct,correlation
FROM pg_stats
WHERE schemaname = 'public';
```

**Solutions:**

1. **Missing Indexes**

   ```sql
   -- Add indexes for common queries
   CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
   CREATE INDEX CONCURRENTLY idx_sessions_user_id ON sessions(user_id);
   CREATE INDEX CONCURRENTLY idx_tokens_expires_at ON tokens(expires_at);
   ```

2. **Database Maintenance**

   ```sql
   -- Update statistics
   ANALYZE;

   -- Vacuum tables
   VACUUM VERBOSE ANALYZE;

   -- Reindex if needed
   REINDEX DATABASE authframework;
   ```

3. **Query Optimization**

   ```sql
   -- Enable query logging
   ALTER SYSTEM SET log_min_duration_statement = 1000;
   SELECT pg_reload_conf();

   -- Check execution plans
   EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'user@example.com';
   ```

### Redis Connection Issues

#### Issue: Cannot Connect to Redis

**Symptoms:**

- Redis connection errors
- Cache functionality not working
- Session storage failures

**Diagnostic Steps:**

```bash
# Test Redis connectivity
redis-cli ping

# Check Redis service
systemctl status redis

# Check Redis logs
tail -f /var/log/redis/redis-server.log

# Test authentication (if password protected)
redis-cli -a your_password ping

# Check Redis configuration
redis-cli CONFIG GET "*"
```

**Solutions:**

1. **Redis Not Running**

   ```bash
   # Start Redis
   sudo systemctl start redis
   sudo systemctl enable redis

   # Check status
   sudo systemctl status redis
   ```

2. **Authentication Issues**

   ```bash
   # Check Redis password configuration
   redis-cli CONFIG GET requirepass

   # Update password in configuration
   export REDIS_URL="redis://:new_password@localhost:6379"
   ```

3. **Memory Issues**

   ```bash
   # Check Redis memory usage
   redis-cli INFO memory

   # Check maxmemory setting
   redis-cli CONFIG GET maxmemory

   # Adjust memory settings
   redis-cli CONFIG SET maxmemory 256mb
   redis-cli CONFIG SET maxmemory-policy allkeys-lru
   ```

### Authentication Issues

#### Issue: Users Cannot Log In

**Symptoms:**

- Valid credentials rejected
- "Invalid credentials" errors
- Inconsistent authentication behavior

**Diagnostic Steps:**

```bash
# Check authentication logs
journalctl -u auth-framework | grep -i "auth"

# Test with curl
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test@example.com","password":"password123"}'

# Check user database
psql -h localhost -U auth_user -d authframework -c \
  "SELECT id, email, created_at, last_login FROM users WHERE email = 'test@example.com';"

# Check password hash
psql -h localhost -U auth_user -d authframework -c \
  "SELECT password_hash FROM users WHERE email = 'test@example.com';"
```

**Solutions:**

1. **Password Hash Mismatch**

   ```bash
   # Reset user password
   auth-framework-cli users reset-password --email test@example.com --password newpassword123

   # Or via SQL
   psql -h localhost -U auth_user -d authframework -c \
     "UPDATE users SET password_hash = crypt('newpassword123', gen_salt('bf')) WHERE email = 'test@example.com';"
   ```

2. **Account Lockout**

   ```bash
   # Check for locked accounts
   auth-framework-cli users list --status locked

   # Unlock account
   auth-framework-cli users unlock --email test@example.com

   # Or via SQL
   psql -h localhost -U auth_user -d authframework -c \
     "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE email = 'test@example.com';"
   ```

3. **Configuration Issues**

   ```toml
   # Check password policy in auth-config.toml
   [security.password]
   min_length = 8  # Ensure user passwords meet requirements
   require_uppercase = false  # Adjust based on existing passwords
   ```

#### Issue: JWT Token Validation Failures

**Symptoms:**

- "Invalid token" errors
- Token expired immediately
- Token signature verification failures

**Diagnostic Steps:**

```bash
# Check JWT configuration
grep -A 10 "\[security\.jwt\]" /app/config/auth-config.toml

# Verify JWT secret
echo $JWT_SECRET | wc -c  # Should be 32+ characters

# Test token creation
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test@example.com","password":"password123"}' | jq .

# Decode JWT token (replace TOKEN with actual token)
echo "TOKEN" | cut -d. -f2 | base64 -d | jq .
```

**Solutions:**

1. **JWT Secret Mismatch**

   ```bash
   # Generate new JWT secret
   export JWT_SECRET=$(openssl rand -base64 32)

   # Update configuration and restart
   systemctl restart auth-framework
   ```

2. **Clock Skew Issues**

   ```bash
   # Check system time
   timedatectl status

   # Sync time
   sudo timedatectl set-ntp true

   # Adjust clock skew tolerance
   [security.jwt]
   clock_skew_tolerance = "60s"
   ```

3. **Token Expiry Configuration**

   ```toml
   # Adjust token expiry times
   [security.jwt]
   access_token_expiry = "1h"
   refresh_token_expiry = "7d"
   ```

### Performance Issues

#### Issue: High Response Times

**Symptoms:**

- Slow API responses
- Timeouts on authentication requests
- Poor user experience

**Diagnostic Steps:**

```bash
# Monitor response times
curl -w "Total time: %{time_total}s\n" -o /dev/null -s http://localhost:8080/health

# Check system load
uptime
top
htop

# Monitor network latency
ping localhost
traceroute localhost

# Check database performance
psql -h localhost -U auth_user -d authframework -c \
  "SELECT query, mean_exec_time, calls FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 5;"
```

**Solutions:**

1. **Database Optimization**

   ```sql
   -- Add missing indexes
   CREATE INDEX CONCURRENTLY idx_users_email_hash ON users USING hash(email);
   CREATE INDEX CONCURRENTLY idx_sessions_expires_at ON sessions(expires_at) WHERE expires_at > NOW();

   -- Update table statistics
   ANALYZE users;
   ANALYZE sessions;
   ANALYZE tokens;
   ```

2. **Connection Pool Tuning**

   ```toml
   # Optimize connection pool settings
   [storage]
   max_connections = 20
   min_connections = 5
   connection_timeout = "30s"
   idle_timeout = "10m"
   ```

3. **Caching Configuration**

   ```toml
   # Enable and tune caching
   [cache]
   enabled = true
   default_ttl = "5m"
   max_memory_mb = 512

   # Cache specific operations
   cache_user_lookups = true
   cache_permission_checks = true
   ```

4. **Rate Limiting Adjustment**

   ```toml
   # Adjust rate limiting if too restrictive
   [rate_limiting]
   requests_per_minute = 120  # Increase if needed
   burst_limit = 20
   ```

#### Issue: High Memory Usage

**Symptoms:**

- Increasing memory consumption
- Out of memory errors
- System swapping

**Diagnostic Steps:**

```bash
# Monitor memory usage
ps -p $(pgrep auth-framework) -o pid,vsz,rss,pmem
cat /proc/$(pgrep auth-framework)/status | grep -E "(VmSize|VmRSS|VmPeak)"

# Check for memory leaks
valgrind --tool=massif --pages-as-heap=yes ./auth-framework &
# Let run for a while, then:
ms_print massif.out.*

# Monitor over time
while true; do
  ps -p $(pgrep auth-framework) -o pid,rss,pmem --no-headers
  sleep 60
done
```

**Solutions:**

1. **Connection Pool Limits**

   ```toml
   # Reduce connection pool sizes
   [storage]
   max_connections = 10

   [cache]
   max_memory_mb = 256
   ```

2. **Log Buffer Limits**

   ```toml
   # Reduce log buffer sizes
   [logging]
   buffer_size = "1MB"
   flush_interval = "10s"
   ```

3. **Session Storage Cleanup**

   ```bash
   # Clean up expired sessions
   auth-framework-cli sessions cleanup --expired

   # Configure automatic cleanup
   [security.session]
   cleanup_interval = "1h"
   ```

### SSL/TLS Issues

#### Issue: SSL Certificate Problems

**Symptoms:**

- "Certificate not trusted" errors
- SSL handshake failures
- Browser security warnings

**Diagnostic Steps:**

```bash
# Test SSL certificate
openssl x509 -in /app/certs/server.crt -text -noout

# Check certificate validity
openssl x509 -in /app/certs/server.crt -noout -dates

# Test SSL connection
openssl s_client -connect localhost:8443 -servername auth.yourdomain.com

# Check certificate chain
openssl verify -CAfile /app/certs/ca.crt /app/certs/server.crt

# Test with curl
curl -v https://auth.yourdomain.com/health
```

**Solutions:**

1. **Certificate Expiry**

   ```bash
   # Renew Let's Encrypt certificate
   sudo certbot renew

   # Copy new certificates
   sudo cp /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem /app/certs/server.crt
   sudo cp /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem /app/certs/server.key

   # Restart service
   systemctl restart auth-framework
   ```

2. **Certificate Chain Issues**

   ```bash
   # Verify certificate chain
   cat /app/certs/server.crt /app/certs/intermediate.crt > /app/certs/fullchain.crt

   # Update configuration
   [security.tls]
   cert_file = "/app/certs/fullchain.crt"
   ```

3. **Hostname Mismatch**

   ```bash
   # Check certificate subject
   openssl x509 -in /app/certs/server.crt -noout -subject

   # Generate new certificate with correct hostname
   openssl req -new -key server.key -out server.csr \
     -subj "/CN=auth.yourdomain.com"
   ```

### Load Balancer and Proxy Issues

#### Issue: Load Balancer Health Checks Failing

**Symptoms:**

- Nodes marked unhealthy
- Traffic not distributed properly
- Intermittent connection issues

**Diagnostic Steps:**

```bash
# Test health endpoint directly
curl -f http://localhost:8080/health

# Check load balancer logs
# For HAProxy:
tail -f /var/log/haproxy.log

# For Nginx:
tail -f /var/log/nginx/error.log

# Check backend connectivity
telnet backend-server 8080
```

**Solutions:**

1. **Health Check Configuration**

   ```bash
   # Ensure health endpoint responds quickly
   curl -w "Time: %{time_total}s\n" http://localhost:8080/health

   # Adjust load balancer timeout
   # HAProxy example:
   timeout check 5s

   # Nginx example:
   proxy_connect_timeout 5s;
   ```

2. **Backend Server Issues**

   ```bash
   # Check all backend servers
   for server in server1 server2 server3; do
     curl -f http://$server:8080/health || echo "$server failed"
   done
   ```

### Monitoring and Alerting Issues

#### Issue: Missing Metrics or Alerts

**Symptoms:**

- No metrics in monitoring dashboard
- Alerts not firing
- Monitoring system shows no data

**Diagnostic Steps:**

```bash
# Check metrics endpoint
curl http://localhost:9090/metrics

# Verify Prometheus configuration
promtool check config /etc/prometheus/prometheus.yml

# Check Prometheus targets
curl http://prometheus:9090/api/v1/targets

# Test alerting rules
promtool check rules /etc/prometheus/rules/*.yml
```

**Solutions:**

1. **Metrics Collection**

   ```toml
   # Enable metrics in auth-config.toml
   [monitoring]
   enabled = true
   metrics_port = 9090
   metrics_path = "/metrics"
   ```

2. **Prometheus Configuration**

   ```yaml
   # Fix scrape configuration
   scrape_configs:
   - job_name: 'auth-framework'
     static_configs:
     - targets: ['auth-framework:9090']
     scrape_interval: 15s
     metrics_path: /metrics
   ```

3. **Firewall Rules**

   ```bash
   # Allow Prometheus to scrape metrics
   sudo ufw allow from prometheus-server-ip to any port 9090
   ```

## Advanced Troubleshooting

### Debug Mode Configuration

Enable debug logging for detailed troubleshooting:

```toml
# Add to auth-config.toml
[logging]
level = "debug"
log_requests = true
log_responses = true
log_sql_queries = true

# Enable specific debug categories
[logging.debug]
authentication = true
authorization = true
database = true
cache = true
security_events = true
```

### Performance Profiling

#### CPU Profiling

```bash
# Install profiling tools
sudo apt install linux-tools-common linux-tools-generic

# Profile CPU usage
sudo perf record -g -p $(pgrep auth-framework)
# Let run for 30 seconds, then Ctrl+C
sudo perf report

# Generate flame graph
git clone https://github.com/brendangregg/FlameGraph
sudo perf script | ./FlameGraph/stackcollapse-perf.pl | ./FlameGraph/flamegraph.pl > auth-framework-cpu.svg
```

#### Memory Profiling

```bash
# Use valgrind for memory analysis
valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
  ./auth-framework --config /app/config/auth-config.toml

# Use heaptrack for heap profiling
heaptrack ./auth-framework --config /app/config/auth-config.toml
heaptrack_gui heaptrack.auth-framework.*
```

### Database Troubleshooting

#### Connection Pool Analysis

```sql
-- Monitor connection pool usage
SELECT
    application_name,
    state,
    count(*) as connection_count
FROM pg_stat_activity
WHERE usename = 'auth_user'
GROUP BY application_name, state;

-- Check for long-running transactions
SELECT
    pid,
    now() - xact_start as transaction_duration,
    query
FROM pg_stat_activity
WHERE xact_start IS NOT NULL
AND now() - xact_start > interval '5 minutes';
```

#### Lock Analysis

```sql
-- Check for blocking queries
SELECT
    blocked_locks.pid AS blocked_pid,
    blocked_activity.usename AS blocked_user,
    blocking_locks.pid AS blocking_pid,
    blocking_activity.usename AS blocking_user,
    blocked_activity.query AS blocked_statement,
    blocking_activity.query AS current_statement_in_blocking_process
FROM pg_catalog.pg_locks blocked_locks
JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
JOIN pg_catalog.pg_locks blocking_locks ON blocking_locks.locktype = blocked_locks.locktype
JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
WHERE NOT blocked_locks.granted;
```

### Network Troubleshooting

#### Connection Analysis

```bash
# Monitor network connections
ss -tulpn | grep auth-framework

# Check for connection leaks
lsof -p $(pgrep auth-framework) | grep TCP

# Monitor connection states
netstat -an | grep :8080 | awk '{print $6}' | sort | uniq -c
```

#### Packet Capture

```bash
# Capture traffic for analysis
sudo tcpdump -i lo -w auth-traffic.pcap port 8080

# Analyze with Wireshark or tshark
tshark -r auth-traffic.pcap -Y "http.request.method == POST"
```

## Prevention and Monitoring

### Automated Health Checks

Create comprehensive health check scripts:

```bash
#!/bin/bash
# /opt/monitoring/health-check.sh

# Function to log with timestamp
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Check service status
if ! systemctl is-active --quiet auth-framework; then
    log_message "CRITICAL: AuthFramework service is down"
    exit 2
fi

# Check HTTP endpoints
if ! curl -sf --max-time 10 http://localhost:8080/health >/dev/null; then
    log_message "CRITICAL: Health endpoint not responding"
    exit 2
fi

# Check database connectivity
if ! timeout 10 psql -h localhost -U auth_user -d authframework -c "SELECT 1" >/dev/null 2>&1; then
    log_message "WARNING: Database connectivity issues"
    exit 1
fi

# Check Redis connectivity
if ! timeout 5 redis-cli ping >/dev/null 2>&1; then
    log_message "WARNING: Redis connectivity issues"
    exit 1
fi

# Check disk space
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 90 ]; then
    log_message "WARNING: Disk usage above 90%: ${DISK_USAGE}%"
    exit 1
fi

# Check memory usage
MEMORY_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [ "$MEMORY_USAGE" -gt 90 ]; then
    log_message "WARNING: Memory usage above 90%: ${MEMORY_USAGE}%"
    exit 1
fi

log_message "OK: All health checks passed"
exit 0
```

### Log Analysis Scripts

```bash
#!/bin/bash
# /opt/monitoring/analyze-logs.sh

LOG_FILE="/app/logs/auth-framework.log"
ALERT_EMAIL="admin@yourdomain.com"

# Check for authentication failures
FAILED_LOGINS=$(grep -c "authentication failed" "$LOG_FILE")
if [ "$FAILED_LOGINS" -gt 100 ]; then
    echo "High number of failed logins: $FAILED_LOGINS" | mail -s "Auth Alert" "$ALERT_EMAIL"
fi

# Check for errors
ERROR_COUNT=$(grep -c "ERROR" "$LOG_FILE")
if [ "$ERROR_COUNT" -gt 50 ]; then
    echo "High error count: $ERROR_COUNT" | mail -s "Error Alert" "$ALERT_EMAIL"
fi

# Check for suspicious patterns
SUSPICIOUS_IPS=$(grep "authentication failed" "$LOG_FILE" | awk '{print $5}' | sort | uniq -c | awk '$1 > 20 {print $2}')
if [ -n "$SUSPICIOUS_IPS" ]; then
    echo "Suspicious IP addresses: $SUSPICIOUS_IPS" | mail -s "Security Alert" "$ALERT_EMAIL"
fi
```

### Performance Monitoring

```bash
#!/bin/bash
# /opt/monitoring/performance-monitor.sh

# Monitor response times
RESPONSE_TIME=$(curl -w "%{time_total}" -o /dev/null -s http://localhost:8080/health)
if (( $(echo "$RESPONSE_TIME > 5.0" | bc -l) )); then
    echo "High response time: ${RESPONSE_TIME}s"
fi

# Monitor connection pool
CONNECTIONS=$(psql -h localhost -U auth_user -d authframework -t -c \
    "SELECT count(*) FROM pg_stat_activity WHERE usename = 'auth_user'")
if [ "$CONNECTIONS" -gt 15 ]; then
    echo "High database connection count: $CONNECTIONS"
fi

# Monitor memory usage
MEMORY_MB=$(ps -p $(pgrep auth-framework) -o rss= | awk '{print $1/1024}')
if (( $(echo "$MEMORY_MB > 1024" | bc -l) )); then
    echo "High memory usage: ${MEMORY_MB}MB"
fi
```

## Emergency Procedures

### Service Recovery

```bash
#!/bin/bash
# /opt/emergency/service-recovery.sh

# Stop service gracefully
systemctl stop auth-framework

# Kill if still running
if pgrep auth-framework; then
    pkill -TERM auth-framework
    sleep 10
    pkill -KILL auth-framework
fi

# Clear any locks
rm -f /var/lock/auth-framework.lock

# Check and fix file permissions
chown -R authframework:authframework /app
chmod 755 /app
chmod 644 /app/config/*.toml
chmod 600 /app/certs/*.key

# Start service
systemctl start auth-framework

# Wait and verify
sleep 30
if curl -sf http://localhost:8080/health; then
    echo "Service recovery successful"
else
    echo "Service recovery failed"
    exit 1
fi
```

### Database Recovery

```bash
#!/bin/bash
# /opt/emergency/database-recovery.sh

# Stop application
systemctl stop auth-framework

# Create backup before recovery
pg_dump -U auth_user -h localhost authframework > /tmp/pre-recovery-backup.sql

# Check database integrity
psql -U auth_user -h localhost authframework -c "SELECT pg_database_size('authframework');"

# Vacuum and analyze
psql -U auth_user -h localhost authframework -c "VACUUM FULL ANALYZE;"

# Restart application
systemctl start auth-framework
```

## Support Resources

### Log Locations

- **Application Logs**: `/app/logs/auth-framework.log`
- **System Logs**: `journalctl -u auth-framework`
- **PostgreSQL Logs**: `/var/log/postgresql/postgresql-*.log`
- **Redis Logs**: `/var/log/redis/redis-server.log`
- **Nginx Logs**: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`

### Configuration Files

- **Main Config**: `/app/config/auth-config.toml`
- **Environment**: `/app/config/.env`
- **Systemd Service**: `/etc/systemd/system/auth-framework.service`
- **PostgreSQL**: `/etc/postgresql/*/main/postgresql.conf`
- **Redis**: `/etc/redis/redis.conf`

### Useful Commands

```bash
# Quick service restart
sudo systemctl restart auth-framework

# Watch logs in real-time
journalctl -u auth-framework -f

# Check configuration
auth-framework --config /app/config/auth-config.toml --validate

# Database connection test
psql -h localhost -U auth_user -d authframework -c "SELECT NOW();"

# Redis connection test
redis-cli ping

# Generate configuration template
auth-framework --generate-config > new-config.toml

# Export metrics
curl -s http://localhost:9090/metrics | grep auth_

# List active sessions
auth-framework-cli sessions list --active
```

### Getting Help

- **Documentation**: [docs.authframework.dev](https://docs.authframework.dev)
- **GitHub Issues**: [github.com/authframework/auth-framework/issues](https://github.com/authframework/auth-framework/issues)
- **Community Forum**: [forum.authframework.dev](https://forum.authframework.dev)
- **Emergency Support**: [emergency@authframework.dev](mailto:emergency@authframework.dev)

When reporting issues, please include:

- AuthFramework version
- Operating system and version
- Configuration file (with secrets redacted)
- Relevant log entries
- Steps to reproduce the issue

---

*AuthFramework v0.4.0 - THE premier authentication and authorization solution*
