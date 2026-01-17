# TDSProxy

TDSProxy is a proxy server for the MS SQL Server TDS (Tabular Data Stream) Protocol. It sits between SQL clients and SQL Server, handling TLS termination and authentication with support for pluggable authenticators.

## Features

- TDS protocol proxy for SQL Server connections
- TLS termination (present your own certificate to clients)
- Configurable TLS to backend SQL Server (TLS 1.0-1.3)
- Pluggable authentication system via MEF
- Credential remapping for backend connections
- Cross-platform support (Windows, Linux, macOS)

## Requirements

- .NET 6.0 SDK or later
- For Docker: Docker Engine

## Building

```bash
# Build the solution
dotnet build src/TDSProxy.sln

# Build in Release mode
dotnet build src/TDSProxy.sln -c Release

# Run tests
dotnet test src/TDSProxy.sln
```

## Running

```bash
# Run the proxy
dotnet run --project src/TDSProxy/TDSProxy.csproj

# With verbose logging
dotnet run --project src/TDSProxy/TDSProxy.csproj -- verbose

# With TDS packet dumping
dotnet run --project src/TDSProxy/TDSProxy.csproj -- packetdump
```

## Docker

The Docker image is based on Debian Bullseye and configured to support TLS 1.0 for legacy SQL Server compatibility.

```bash
# Build the image
docker build -t tdsproxy .

# Run the container
docker run -p 1435:1435 tdsproxy

# Run with custom config
docker run -p 1435:1435 -v $(pwd)/appsettings.json:/app/appsettings.json tdsproxy
```

## Configuration

Edit `appsettings.json` to configure listeners and backend servers:

```json
{
  "Listeners": [
    {
      "Host": "0.0.0.0",
      "Port": 1435,
      "Tls": {
        "Enabled": false,
        "CertificatePath": "",
        "CertificatePassword": "",
        "Protocols": "Tls12,Tls13"
      }
    }
  ],
  "Servers": [
    {
      "Host": "sqlserver.example.com",
      "Port": 1433,
      "Tls": {
        "Enabled": true,
        "ValidateCertificate": false,
        "TrustServerCertificate": true,
        "Protocols": "Tls,Tls11,Tls12"
      }
    }
  ]
}
```

Each listener is paired with a server by array index.

### TLS Protocol Options

- `Tls` - TLS 1.0 (for legacy SQL Server)
- `Tls11` - TLS 1.1
- `Tls12` - TLS 1.2
- `Tls13` - TLS 1.3

## Running on Ubuntu/Linux

### Prerequisites

```bash
# Install .NET 6.0 SDK
wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y dotnet-sdk-6.0
```

### TLS 1.0 Support

Modern Ubuntu disables TLS 1.0 by default. If you need to connect to legacy SQL Servers requiring TLS 1.0, create a custom OpenSSL config:

```bash
# Create custom OpenSSL config
cat > /etc/ssl/openssl-tls1.cnf << 'EOF'
openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
MinProtocol = TLSv1
CipherString = DEFAULT:@SECLEVEL=0
EOF

# Run with custom OpenSSL config
OPENSSL_CONF=/etc/ssl/openssl-tls1.cnf dotnet run --project src/TDSProxy/TDSProxy.csproj
```

### Running as a systemd Service

```bash
# Create service file
sudo cat > /etc/systemd/system/tdsproxy.service << 'EOF'
[Unit]
Description=TDS Proxy Server
After=network.target

[Service]
Type=simple
User=tdsproxy
WorkingDirectory=/opt/tdsproxy
Environment=OPENSSL_CONF=/etc/ssl/openssl-tls1.cnf
ExecStart=/usr/bin/dotnet TDSProxy.dll
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable tdsproxy
sudo systemctl start tdsproxy
```

## Architecture

### Project Structure

| Project | Description |
|---------|-------------|
| **TDSProxy** | Main executable, hosts proxy service and manages connections |
| **TDSProtocol** | Core library for TDS protocol parsing/serialization |
| **TDSProxy.Authentication** | Authentication interface for plugin-based authenticators (MEF) |
| **SampleAuthenticator** | Example authenticator implementation |
| **TDSProtocolTests** | Unit tests for protocol handling |
| **TestConnection** | Test utility for SQL connections |

### Connection Flow

1. **TDSProxyService** - Hosted service that starts listeners
2. **TDSListener** - TCP listener accepting connections
3. **TDSConnection** - Handles full connection lifecycle:
   - PreLogin message exchange
   - SSL/TLS handshake with client
   - Optional TLS to backend SQL Server
   - Login7 authentication with pluggable authenticators
   - Bidirectional packet forwarding

### Authentication Plugins

Authenticators implement `IAuthenticator` and are loaded via MEF. Place authenticator DLLs in the application directory. If no authenticators are configured, credentials pass through unchanged.

## Changelog

### Recent Changes

- **Pass through credentials** - When no authenticators are configured, client credentials are passed through to the backend server unchanged
- **Fix Buffer.BlockCopy bug** - Fixed SSL handshake adapter buffer handling
- **Custom OpenSSL config** - Use `OPENSSL_CONF` environment variable for TLS 1.0 support
- **Debian Bullseye Docker image** - Use Bullseye base image with OpenSSL configured for TLS 1.0
- **Docker support** - Added Dockerfile with TLS 1.0 configuration
- **Downgrade to .NET 6.0** - Changed from .NET 7.0 to .NET 6.0 for broader Linux compatibility and LTS support

## License

See LICENSE file for details.
