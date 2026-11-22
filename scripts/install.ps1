# AuthFramework Installation Script for Windows
# Usage: iwr -useb https://raw.githubusercontent.com/ciresnave/auth-framework/main/scripts/install.ps1 | iex

$ErrorActionPreference = 'Stop'

# Configuration
$REPO = 'ciresnave/auth-framework'
# The release publishes auth-framework-windows-x86_64.zip (server) and auth-framework-admin-windows-x86_64.zip, each
# holding <archive name>.exe; there is no version in the asset name and no ARM64 build.
$BINARY_NAME = 'auth-framework'
$INSTALL_DIR = "${env:ProgramFiles}\AuthFramework"
$CONFIG_DIR = "${env:USERPROFILE}\.config\authframework"
$TEMP_DIR = "${env:TEMP}\authframework-install"

# Create temp directory
if (Test-Path $TEMP_DIR) {
    Remove-Item -Path $TEMP_DIR -Recurse -Force
}
New-Item -ItemType Directory -Path $TEMP_DIR | Out-Null

# Helper Functions
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = 'White',
        [string]$Prefix = ''
    )
    
    if ($Prefix) {
        Write-Host "$Prefix " -NoNewline -ForegroundColor $Color
    }
    Write-Host $Message
}

function Write-Info {
    param([string]$Message)
    Write-ColorOutput -Message $Message -Color Cyan -Prefix 'ℹ'
}

function Write-Success {
    param([string]$Message)
    Write-ColorOutput -Message $Message -Color Green -Prefix '✓'
}

function Write-Error {
    param([string]$Message)
    Write-ColorOutput -Message $Message -Color Red -Prefix '✗'
}

function Write-Warning {
    param([string]$Message)
    Write-ColorOutput -Message $Message -Color Yellow -Prefix '⚠'
}

function Get-LatestVersion {
    try {
        Write-Info 'Fetching latest version...'
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$REPO/releases/latest"
        $version = $response.tag_name
        
        if ([string]::IsNullOrEmpty($version)) {
            throw 'Failed to get latest version'
        }
        
        Write-Success "Latest version: $version"
        return $version
    }
    catch {
        Write-Error "Failed to fetch latest version: $_"
        exit 1
    }
}

function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    
    switch ($arch) {
        'AMD64' { return 'x86_64' }
        'ARM64' {
            Write-Error 'No Windows ARM64 build is published (only windows-x86_64)'
            exit 1
        }
        default {
            Write-Error "Unsupported architecture: $arch"
            exit 1
        }
    }
}

function Download-And-Install {
    param(
        [string]$Version,
        [string]$Arch
    )
    
    $TARGET = "windows-${Arch}"
    $baseUrl = "https://github.com/${REPO}/releases/download/${Version}"
    
    Write-Info "Downloading AuthFramework ${Version} for ${TARGET}..."
    
    try {
        # Each archive holds one <stem>.exe; install it under its command name
        $stems = @{
            "${BINARY_NAME}-${TARGET}"       = "${BINARY_NAME}.exe"
            "${BINARY_NAME}-admin-${TARGET}" = "${BINARY_NAME}-admin.exe"
        }
        
        # Create install directory
        if (-not (Test-Path $INSTALL_DIR)) {
            New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
        }
        
        foreach ($stem in $stems.Keys) {
            $archivePath = Join-Path $TEMP_DIR "${stem}.zip"
            try {
                Invoke-WebRequest -Uri "${baseUrl}/${stem}.zip" -OutFile $archivePath -UseBasicParsing
            }
            catch {
                if ($stem -like "${BINARY_NAME}-admin-*") {
                    Write-Warning "No admin binary published for ${TARGET}; installing the server only"
                    continue
                }
                throw
            }
            
            Write-Info "Extracting ${stem}.zip..."
            Expand-Archive -Path $archivePath -DestinationPath $TEMP_DIR -Force
            
            $sourcePath = Join-Path $TEMP_DIR "${stem}.exe"
            if (-not (Test-Path $sourcePath)) {
                throw "${stem}.zip does not contain ${stem}.exe"
            }
            Copy-Item -Path $sourcePath -Destination (Join-Path $INSTALL_DIR $stems[$stem]) -Force
            Write-Success "Installed $($stems[$stem])"
        }
        
        # Add to PATH if not already present
        $currentPath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        if ($currentPath -notlike "*$INSTALL_DIR*") {
            Write-Info "Adding ${INSTALL_DIR} to system PATH..."
            [Environment]::SetEnvironmentVariable(
                'Path',
                "$currentPath;$INSTALL_DIR",
                'Machine'
            )
            Write-Success 'Added to PATH (restart terminal to use)'
        }
        
        Write-Success 'AuthFramework installed successfully!'
    }
    catch {
        Write-Error "Installation failed: $_"
        exit 1
    }
}

function Create-SampleConfig {
    Write-Info 'Creating sample configuration...'
    
    if (-not (Test-Path $CONFIG_DIR)) {
        New-Item -ItemType Directory -Path $CONFIG_DIR -Force | Out-Null
    }
    
    $configPath = Join-Path $CONFIG_DIR 'config.toml'
    
    $configContent = @"
# AuthFramework Configuration File
# Generated by install script

[server]
host = "127.0.0.1"
port = 8080
workers = 4

[storage]
# Options: "memory", "sqlite", "postgres", "redis"
backend = "sqlite"
connection_string = "${env:LOCALAPPDATA}\authframework\data.db"

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
"@
    
    Set-Content -Path $configPath -Value $configContent
    
    Write-Success "Sample configuration created at ${configPath}"
    Write-Warning 'Remember to update the secret_key and other settings before running in production!'
}

function Install-WindowsService {
    $response = Read-Host 'Install as Windows Service? (y/N)'
    if ($response -ne 'y' -and $response -ne 'Y') {
        return
    }
    
    Write-Info 'Installing Windows Service...'
    
    $serviceName = 'AuthFramework'
    $displayName = 'AuthFramework Authentication Server'
    $description = 'AuthFramework - High-performance authentication and authorization server'
    $binaryPath = Join-Path $INSTALL_DIR 'auth-framework.exe'
    $configPath = Join-Path $CONFIG_DIR 'config.toml'
    
    # Stop service if it exists
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Info 'Stopping existing service...'
        Stop-Service -Name $serviceName -Force
        sc.exe delete $serviceName | Out-Null
        Start-Sleep -Seconds 2
    }
    
    # Create service
    try {
        New-Service -Name $serviceName `
            -BinaryPathName "`"$binaryPath`" --config `"$configPath`"" `
            -DisplayName $displayName `
            -Description $description `
            -StartupType Manual
        
        Write-Success 'Windows Service installed successfully!'
        Write-Info "To start: Start-Service -Name $serviceName"
        Write-Info "To enable auto-start: Set-Service -Name $serviceName -StartupType Automatic"
    }
    catch {
        Write-Error "Failed to create service: $_"
    }
}

function Create-FirewallRule {
    $response = Read-Host 'Create Windows Firewall rule? (y/N)'
    if ($response -ne 'y' -and $response -ne 'Y') {
        return
    }
    
    Write-Info 'Creating Windows Firewall rule...'
    
    $ruleName = 'AuthFramework Server'
    $binaryPath = Join-Path $INSTALL_DIR 'auth-framework.exe'
    
    # Remove existing rule if present
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existingRule) {
        Remove-NetFirewallRule -DisplayName $ruleName
    }
    
    try {
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound `
            -Program $binaryPath `
            -Action Allow `
            -Profile Any `
            -Description 'Allow AuthFramework Server traffic'
        
        Write-Success 'Firewall rule created successfully!'
    }
    catch {
        Write-Error "Failed to create firewall rule: $_"
        Write-Info 'You may need to run this script as Administrator'
    }
}

function Show-UsageInstructions {
    Write-Host ''
    Write-Host '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' -ForegroundColor Green
    Write-Host '  AuthFramework Installation Complete!' -ForegroundColor Green
    Write-Host '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' -ForegroundColor Green
    Write-Host ''
    Write-Host 'Quick Start:' -ForegroundColor Cyan
    Write-Host '  1. Edit configuration:'
    Write-Host "     PS> notepad $CONFIG_DIR\config.toml"
    Write-Host ''
    Write-Host '  2. Generate a secure secret key:'
    Write-Host '     PS> [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))'
    Write-Host ''
    Write-Host '  3. Start the server:'
    Write-Host '     PS> auth-framework'
    Write-Host ''
    Write-Host '  4. Or use the CLI:'
    Write-Host '     PS> auth-framework-admin --help'
    Write-Host ''
    Write-Host 'Windows Service:' -ForegroundColor Cyan
    Write-Host '  PS> Start-Service -Name AuthFramework'
    Write-Host '  PS> Set-Service -Name AuthFramework -StartupType Automatic'
    Write-Host ''
    Write-Host 'Documentation:' -ForegroundColor Cyan
    Write-Host "  https://github.com/$REPO/blob/main/README.md"
    Write-Host ''
    Write-Host 'API Documentation:' -ForegroundColor Cyan
    Write-Host '  http://localhost:8080/api/docs (when server is running)'
    Write-Host ''
    Write-Host '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' -ForegroundColor Green
    Write-Host ''
    Write-Warning "Note: Restart your terminal to use the 'auth-framework*' commands"
}

# Main installation flow
function Main {
    Write-Host ''
    Write-Host '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' -ForegroundColor Cyan
    Write-Host '  AuthFramework Installer for Windows' -ForegroundColor Cyan
    Write-Host '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' -ForegroundColor Cyan
    Write-Host ''
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning 'Not running as Administrator - some features may be unavailable'
        Write-Info 'For full functionality, run: Start-Process powershell -Verb RunAs'
        Write-Host ''
    }
    
    # Detect architecture
    Write-Info 'Detecting architecture...'
    $arch = Get-Architecture
    Write-Success "Detected architecture: $arch"
    
    # Get latest version
    $version = Get-LatestVersion
    
    # Download and install
    Download-And-Install -Version $version -Arch $arch
    
    # Create configuration
    Create-SampleConfig
    
    # Install Windows Service (if admin)
    if ($isAdmin) {
        Install-WindowsService
        Create-FirewallRule
    }
    else {
        Write-Warning 'Skipping Windows Service and Firewall setup (requires Administrator)'
    }
    
    # Cleanup
    Write-Info 'Cleaning up temporary files...'
    Remove-Item -Path $TEMP_DIR -Recurse -Force -ErrorAction SilentlyContinue
    
    # Show usage instructions
    Show-UsageInstructions
}

# Run main function
try {
    Main
}
catch {
    Write-Error "Installation failed: $_"
    exit 1
}
