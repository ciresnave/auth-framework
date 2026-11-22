#!/usr/bin/env bash
# AuthFramework Installation Script
# Supports Linux and macOS
# Usage: curl -sSL https://raw.githubusercontent.com/ciresnave/auth-framework/main/scripts/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="ciresnave/auth-framework"
# The release publishes auth-framework-<os>-<arch>[-musl].tar.gz (server) and auth-framework-admin-<os>-<arch>[-musl].tar.gz,
# each holding one binary of the same name as the archive; there is no version in the asset name.
BINARY_NAME="auth-framework"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
TEMP_DIR=$(mktemp -d)

# Functions
print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

cleanup() {
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

detect_platform() {
    local OS
    local ARCH
    
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case "$OS" in
        linux*)
            OS="linux"
            ;;
        darwin*)
            OS="macos"
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    case "$ARCH" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    # TARGET is the platform part of the release asset name: <os>-<arch>, plus -musl on a musl Linux.
    TARGET="${OS}-${ARCH}"
    if [ "$OS" = "linux" ] && ldd --version 2>&1 | grep -q musl; then
        TARGET="${TARGET}-musl"
    fi
    
    echo "$TARGET"
}

get_latest_version() {
    local VERSION
    VERSION=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [ -z "$VERSION" ]; then
        print_error "Failed to get latest version"
        exit 1
    fi
    
    echo "$VERSION"
}

fetch_asset() {
    # fetch_asset <asset stem>: download <stem>.tar.gz from the release, check it against <stem>.tar.gz.sha256,
    # and extract the binary <stem> into the current directory. Returns non-zero if the download fails.
    local STEM=$1
    local ARCHIVE_NAME="${STEM}.tar.gz"
    local BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

    if ! curl -sSLf -o "$ARCHIVE_NAME" "${BASE_URL}/${ARCHIVE_NAME}"; then
        return 1
    fi
    if curl -sSLf -o "${ARCHIVE_NAME}.sha256" "${BASE_URL}/${ARCHIVE_NAME}.sha256"; then
        local EXPECTED ACTUAL
        EXPECTED=$(awk '{print $1}' "${ARCHIVE_NAME}.sha256")
        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL=$(sha256sum "$ARCHIVE_NAME" | awk '{print $1}')
        else
            ACTUAL=$(shasum -a 256 "$ARCHIVE_NAME" | awk '{print $1}')
        fi
        if [ "$EXPECTED" != "$ACTUAL" ]; then
            print_error "Checksum mismatch for ${ARCHIVE_NAME}"
            exit 1
        fi
    else
        print_warning "No checksum published for ${ARCHIVE_NAME}; not verified"
    fi
    tar xzf "$ARCHIVE_NAME"
}

download_and_install() {
    VERSION=$1
    local TARGET=$2
    local SERVER_STEM="${BINARY_NAME}-${TARGET}"
    local ADMIN_STEM="${BINARY_NAME}-admin-${TARGET}"

    print_info "Downloading AuthFramework ${VERSION} for ${TARGET}..."

    cd "$TEMP_DIR"

    if ! fetch_asset "$SERVER_STEM"; then
        print_error "Failed to download ${SERVER_STEM}.tar.gz from the ${VERSION} release"
        exit 1
    fi
    if ! fetch_asset "$ADMIN_STEM"; then
        print_warning "No admin binary published for ${TARGET}; installing the server only"
    fi

    print_info "Installing binaries to ${INSTALL_DIR}..."

    # Check if we need sudo
    if [ -w "$INSTALL_DIR" ]; then
        SUDO=""
    else
        SUDO="sudo"
        print_warning "Installing to ${INSTALL_DIR} requires elevated privileges"
    fi

    # Each archive holds one binary named like the archive; install it under its command name
    if [ -f "$SERVER_STEM" ]; then
        $SUDO install -m 755 "$SERVER_STEM" "$INSTALL_DIR/${BINARY_NAME}"
        print_success "Installed ${BINARY_NAME}"
    fi
    if [ -f "$ADMIN_STEM" ]; then
        $SUDO install -m 755 "$ADMIN_STEM" "$INSTALL_DIR/${BINARY_NAME}-admin"
        print_success "Installed ${BINARY_NAME}-admin"
    fi

    # Verify installation
    if [ -x "$INSTALL_DIR/${BINARY_NAME}" ]; then
        print_success "AuthFramework installed successfully!"
        print_info "Version: $("$INSTALL_DIR/${BINARY_NAME}" --version 2>/dev/null || echo 'unknown')"
    else
        print_error "Installation failed - ${BINARY_NAME} not found in ${INSTALL_DIR}"
        exit 1
    fi
}

create_sample_config() {
    local CONFIG_DIR="${HOME}/.config/authframework"
    
    print_info "Creating sample configuration..."
    
    mkdir -p "$CONFIG_DIR"
    
    cat > "${CONFIG_DIR}/config.toml" << 'EOF'
# AuthFramework Configuration File
# Generated by install script

[server]
host = "127.0.0.1"
port = 8080
workers = 4

[storage]
# Options: "memory", "sqlite", "postgres", "redis"
backend = "sqlite"
connection_string = "${HOME}/.local/share/authframework/data.db"

[security]
# Generate a secure secret key:
# openssl rand -base64 32
secret_key = "CHANGE_THIS_TO_A_SECURE_RANDOM_KEY"

[jwt]
issuer = "authframework"
access_token_ttl = 3600      # 1 hour
refresh_token_ttl = 2592000  # 30 days

[rate_limiting]
enabled = true
requests_per_second = 100
burst_size = 200

[cors]
enabled = true
allowed_origins = ["http://localhost:3000", "http://localhost:8080"]

[logging]
level = "info"
format = "json"

# OAuth 2.0 Configuration
[oauth]
enable_pkce = true
authorization_code_ttl = 600  # 10 minutes

# WebAuthn Configuration
[webauthn]
rp_name = "AuthFramework"
rp_id = "localhost"
rp_origin = "http://localhost:8080"

# SAML Configuration
[saml]
entity_id = "http://localhost:8080/saml"
acs_url = "http://localhost:8080/api/v1/saml/acs"
EOF
    
    print_success "Sample configuration created at ${CONFIG_DIR}/config.toml"
    print_warning "Remember to update the secret_key and other settings before running in production!"
}

create_systemd_service() {
    if [ ! -d "/etc/systemd/system" ]; then
        print_info "Systemd not detected, skipping service creation"
        return
    fi
    
    print_info "Creating systemd service..."
    
    local SERVICE_FILE="/etc/systemd/system/authframework.service"
    
    sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=AuthFramework Authentication Server
After=network.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${HOME}
ExecStart=${INSTALL_DIR}/auth-framework --config ${HOME}/.config/authframework/config.toml
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    
    print_success "Systemd service created at ${SERVICE_FILE}"
    print_info "To start the service: sudo systemctl start authframework"
    print_info "To enable on boot: sudo systemctl enable authframework"
}

print_usage_instructions() {
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  AuthFramework Installation Complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${BLUE}Quick Start:${NC}"
    echo "  1. Edit configuration:"
    echo "     \$ vi ~/.config/authframework/config.toml"
    echo ""
    echo "  2. Generate a secure secret key:"
    echo "     \$ openssl rand -base64 32"
    echo ""
    echo "  3. Start the server:"
    echo "     \$ auth-framework"
    echo ""
    echo "  4. Or use the CLI:"
    echo "     \$ auth-framework-admin --help"
    echo ""
    echo -e "${BLUE}Systemd Service:${NC}"
    if [ -d "/etc/systemd/system" ]; then
        echo "  \$ sudo systemctl start authframework"
        echo "  \$ sudo systemctl enable authframework"
    else
        echo "  Systemd not available on this system"
    fi
    echo ""
    echo -e "${BLUE}Documentation:${NC}"
    echo "  https://github.com/${REPO}/blob/main/README.md"
    echo ""
    echo -e "${BLUE}API Documentation:${NC}"
    echo "  http://localhost:8080/api/docs (when server is running)"
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Main installation flow
main() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  AuthFramework Installer${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Check dependencies
    for cmd in curl tar; do
        if ! command -v $cmd >/dev/null 2>&1; then
            print_error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    # Detect platform
    print_info "Detecting platform..."
    TARGET=$(detect_platform)
    print_success "Detected platform: $TARGET"
    
    # Get latest version
    print_info "Fetching latest version..."
    VERSION=$(get_latest_version)
    print_success "Latest version: $VERSION"
    
    # Download and install
    download_and_install "$VERSION" "$TARGET"
    
    # Create configuration
    create_sample_config
    
    # Create systemd service (if applicable)
    if [ "$OS" = "linux" ]; then
        read -p "Create systemd service? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            create_systemd_service
        fi
    fi
    
    # Print usage instructions
    print_usage_instructions
}

# Run main function
main "$@"
