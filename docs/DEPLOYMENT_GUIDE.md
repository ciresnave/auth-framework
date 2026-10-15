# AuthFramework Precompiled Releases - Deployment Guide

## 🚀 Quick Installation

AuthFramework provides precompiled binaries for easy deployment without needing Rust installed.

### One-Line Installation

**Linux/macOS:**

```bash
curl -sSL https://raw.githubusercontent.com/ciresnave/auth-framework/main/scripts/install.sh | bash
```

**Windows PowerShell (Run as Administrator):**

```powershell
iwr -useb https://raw.githubusercontent.com/ciresnave/auth-framework/main/scripts/install.ps1 | iex
```

### Docker (Recommended for Production)

```bash
# Using Docker Compose
docker compose up -d

# Or using Docker directly
docker pull ghcr.io/ciresnave/auth-framework:latest
docker run -p 8080:8080 ghcr.io/ciresnave/auth-framework:latest
```

---

## 📦 Platform Support

### Precompiled Binaries Available

| Platform         | Architecture            | Binary Package                                          |
| ---------------- | ----------------------- | ------------------------------------------------------- |
| **Linux (GNU)**  | x86_64 (Intel/AMD)      | `authframework-vX.X.X-x86_64-unknown-linux-gnu.tar.gz`  |
| **Linux (musl)** | x86_64 (Intel/AMD)      | `authframework-vX.X.X-x86_64-unknown-linux-musl.tar.gz` |
| **Linux (GNU)**  | aarch64 (ARM64)         | `authframework-vX.X.X-aarch64-unknown-linux-gnu.tar.gz` |
| **macOS**        | x86_64 (Intel)          | `authframework-vX.X.X-x86_64-apple-darwin.tar.gz`       |
| **macOS**        | aarch64 (Apple Silicon) | `authframework-vX.X.X-aarch64-apple-darwin.tar.gz`      |
| **Windows**      | x86_64 (Intel/AMD)      | `authframework-vX.X.X-x86_64-pc-windows-msvc.zip`       |
| **Windows**      | aarch64 (ARM64)         | `authframework-vX.X.X-aarch64-pc-windows-msvc.zip`      |

---

## 🔧 Manual Installation

### 1. Download Binaries

Visit the [releases page](https://github.com/ciresnave/auth-framework/releases) and download the appropriate package for your platform.

### 2. Extract Archive

**Linux/macOS:**

```bash
tar xzf authframework-v*.tar.gz
```

**Windows:**

```powershell
Expand-Archive authframework-v*.zip
```

### 3. Install Binaries

**Linux/macOS:**

```bash
sudo install -m 755 authframework-server /usr/local/bin/
sudo install -m 755 authframework-cli /usr/local/bin/
```

**Windows:**

```powershell
# Copy to Program Files
Copy-Item authframework-*.exe "C:\Program Files\AuthFramework\"

# Add to PATH
$env:Path += ";C:\Program Files\AuthFramework"
[Environment]::SetEnvironmentVariable("Path", $env:Path, "Machine")
```

### 4. Verify Installation

```bash
authframework-server --version
authframework-cli --version
```

---

## ⚙️ Configuration

### Quick Start Configuration

The installation script creates a sample configuration at:

- **Linux/macOS:** `~/.config/authframework/config.toml`
- **Windows:** `%USERPROFILE%\.config\authframework\config.toml`

### Minimal Configuration

```toml
[server]
host = "127.0.0.1"
port = 8080

[storage]
backend = "sqlite"
connection_string = "/path/to/data.db"

[security]
secret_key = "GENERATE_A_SECURE_KEY_HERE"

[jwt]
issuer = "authframework"
access_token_ttl = 3600
refresh_token_ttl = 2592000
```

### Generate Secure Keys

**Linux/macOS:**

```bash
openssl rand -base64 32
```

**Windows:**

```powershell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
```

### Environment Variables

You can also configure using environment variables:

```bash
export SERVER_HOST="0.0.0.0"
export SERVER_PORT="8080"
export STORAGE_BACKEND="postgres"
export DATABASE_URL="postgresql://user:pass@localhost/authframework"
export SECRET_KEY="your-secret-key"
export JWT_ISSUER="authframework"
export RUST_LOG="info"
```

---

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)

1. **Clone or download the docker-compose.yml:**

```bash
curl -O https://raw.githubusercontent.com/ciresnave/auth-framework/main/docker-compose.yml
```

1. **Create environment file (.env):**

```bash
cat > .env << EOF
# Database
DB_PASSWORD=your_secure_db_password

# Redis
REDIS_PASSWORD=your_secure_redis_password

# JWT
JWT_SECRET=your_super_secret_jwt_key

# Security
SECRET_KEY=$(openssl rand -base64 32)
EOF
```

1. **Start services:**

```bash
# Start core services
docker compose up -d

# Start with monitoring (Prometheus + Grafana)
docker compose --profile monitoring up -d

# Start with admin tools (pgAdmin)
docker compose --profile admin up -d

# Start everything
docker compose --profile monitoring --profile admin up -d
```

1. **Check status:**

```bash
docker compose ps
docker compose logs -f authframework
```

### Using Docker Directly

```bash
# Pull image
docker pull ghcr.io/ciresnave/auth-framework:latest

# Run with SQLite (simplest)
docker run -d \
  --name authframework \
  -p 8080:8080 \
  -e STORAGE_BACKEND=sqlite \
  -e SECRET_KEY="$(openssl rand -base64 32)" \
  -v authframework-data:/app/data \
  ghcr.io/ciresnave/auth-framework:latest

# Run with PostgreSQL
docker run -d \
  --name authframework \
  -p 8080:8080 \
  -e STORAGE_BACKEND=postgres \
  -e DATABASE_URL="postgresql://user:pass@postgres:5432/authframework" \
  -e SECRET_KEY="$(openssl rand -base64 32)" \
  --network your-network \
  ghcr.io/ciresnave/auth-framework:latest
```

### Docker Tags

- `latest` - Latest stable release
- `vX.Y.Z` - Specific version
- `vX.Y` - Latest patch for minor version
- `vX` - Latest minor version for major version

---

## 🎯 Running as a Service

### Linux (systemd)

The installation script can create a systemd service. Manually:

1. **Create service file:**

```bash
sudo tee /etc/systemd/system/authframework.service > /dev/null << EOF
[Unit]
Description=AuthFramework Authentication Server
After=network.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${HOME}
ExecStart=/usr/local/bin/authframework-server --config ${HOME}/.config/authframework/config.toml
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
```

1. **Enable and start:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable authframework
sudo systemctl start authframework
sudo systemctl status authframework
```

1. **View logs:**

```bash
sudo journalctl -u authframework -f
```

### macOS (launchd)

1. **Create plist file:**

```bash
cat > ~/Library/LaunchAgents/com.authframework.server.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.authframework.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/authframework-server</string>
        <string>--config</string>
        <string>${HOME}/.config/authframework/config.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${HOME}/Library/Logs/authframework.log</string>
    <key>StandardErrorPath</key>
    <string>${HOME}/Library/Logs/authframework-error.log</string>
</dict>
</plist>
EOF
```

1. **Load and start:**

```bash
launchctl load ~/Library/LaunchAgents/com.authframework.server.plist
launchctl start com.authframework.server
```

### Windows (Service)

The PowerShell installation script can install as a Windows Service. Manually:

```powershell
# Create service
New-Service -Name "AuthFramework" `
            -BinaryPathName '"C:\Program Files\AuthFramework\authframework-server.exe" --config "C:\Users\YourUser\.config\authframework\config.toml"' `
            -DisplayName "AuthFramework Server" `
            -Description "AuthFramework Authentication Server" `
            -StartupType Automatic

# Start service
Start-Service -Name "AuthFramework"

# Check status
Get-Service -Name "AuthFramework"
```

---

## 🔒 Production Checklist

Before deploying to production:

### Security

- [ ] Generate strong `SECRET_KEY` using crypto-secure random
- [ ] Use strong database passwords
- [ ] Enable HTTPS (use reverse proxy like nginx/Caddy)
- [ ] Configure CORS appropriately
- [ ] Enable rate limiting
- [ ] Review firewall rules
- [ ] Set up fail2ban or similar

### Configuration

- [ ] Use PostgreSQL (not SQLite) for production
- [ ] Configure Redis for session storage
- [ ] Set appropriate JWT token TTLs
- [ ] Configure proper logging level
- [ ] Set up log rotation
- [ ] Configure backup strategy

### Monitoring

- [ ] Set up health check monitoring
- [ ] Configure metrics collection (Prometheus)
- [ ] Set up alerting (PagerDuty, etc.)
- [ ] Configure log aggregation (ELK, Loki, etc.)
- [ ] Set up uptime monitoring

### High Availability

- [ ] Deploy multiple instances behind load balancer
- [ ] Use managed database (AWS RDS, Azure Database, etc.)
- [ ] Use Redis cluster for session storage
- [ ] Configure automatic failover
- [ ] Set up database replication

---

## 📊 Monitoring and Observability

### Health Endpoints

```bash
# Basic health check
curl http://localhost:8080/health

# Detailed health (includes dependencies)
curl http://localhost:8080/health/detailed

# Readiness check
curl http://localhost:8080/readiness

# Liveness check
curl http://localhost:8080/liveness

# Prometheus metrics
curl http://localhost:8080/metrics
```

### Prometheus Configuration

Create `monitoring/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'authframework'
    static_configs:
      - targets: ['authframework:8080']
    metrics_path: '/metrics'
```

### Grafana Dashboard

Import the AuthFramework dashboard (ID: TBD) or create custom dashboards monitoring:

- Request rate and latency
- Authentication success/failure rates
- Token issuance rates
- Database connection pool stats
- Memory and CPU usage

---

## 🔄 Updates and Upgrades

### Check for Updates

```bash
# Check current version
authframework-server --version

# Check latest release
curl -s https://api.github.com/repos/ciresnave/auth-framework/releases/latest | grep tag_name
```

### Update Installation

**Using install script:**

```bash
# Linux/macOS
curl -sSL https://raw.githubusercontent.com/ciresnave/auth-framework/main/scripts/install.sh | bash

# Windows
iwr -useb https://raw.githubusercontent.com/ciresnave/auth-framework/main/scripts/install.ps1 | iex
```

**Docker:**

```bash
docker compose pull
docker compose up -d
```

### Database Migrations

```bash
# Run migrations
authframework-cli migrate up

# Check migration status
authframework-cli migrate status

# Rollback if needed
authframework-cli migrate down
```

---

## 🐛 Troubleshooting

### Common Issues

**Port already in use:**

```bash
# Find process using port 8080
lsof -i :8080  # Linux/macOS
netstat -ano | findstr :8080  # Windows

# Change port in config or environment
export SERVER_PORT=8081
```

**Database connection failed:**

```bash
# Check database is running
pg_isready -h localhost -p 5432

# Test connection
psql -h localhost -U auth_user -d authframework

# Check connection string format
DATABASE_URL=postgresql://user:pass@host:5432/database
```

**Permission denied:**

```bash
# Linux/macOS: Fix binary permissions
chmod +x /usr/local/bin/authframework-server

# Check file ownership
ls -l /usr/local/bin/authframework-*
```

### Enable Debug Logging

```bash
export RUST_LOG=debug
authframework-server
```

### Getting Help

- 📚 Documentation: <https://github.com/ciresnave/auth-framework/tree/main/docs>
- 🐛 Issues: <https://github.com/ciresnave/auth-framework/issues>
- 💬 Discussions: <https://github.com/ciresnave/auth-framework/discussions>

---

## 📝 Next Steps

After installation:

1. **Configure for your environment** - Edit config.toml
2. **Initialize database** - Run migrations if using PostgreSQL
3. **Create admin user** - Use authframework-cli
4. **Test endpoints** - Use curl or Postman
5. **Integrate with your app** - Use SDK or REST API
6. **Set up monitoring** - Configure health checks and metrics
7. **Deploy to production** - Follow production checklist

## 🎉 Success

You now have AuthFramework running! Access the API documentation at:

- <http://localhost:8080/docs> (Swagger UI when the API server is running)
- <http://localhost:8080/api/openapi.json> (OpenAPI JSON)

For SDK examples, see:

- JavaScript/TypeScript: `sdks/javascript/`
- Python: `sdks/python/`
- Go: `sdks/go/` (coming soon)
- Java: `sdks/java/` (coming soon)
