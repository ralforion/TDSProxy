# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build the solution
dotnet build src/TDSProxy.sln

# Build in Release mode
dotnet build src/TDSProxy.sln -c Release

# Run tests (xUnit)
dotnet test src/TDSProxy.sln

# Run a specific test class
dotnet test src/TDSProtocolTests/TDSProtocolTests.csproj --filter "FullyQualifiedName~TDSPreLoginMessageTests"

# Run the proxy
dotnet run --project src/TDSProxy/TDSProxy.csproj

# Run with debug options
dotnet run --project src/TDSProxy/TDSProxy.csproj -- verbose    # Enable verbose logging
dotnet run --project src/TDSProxy/TDSProxy.csproj -- packetdump # Dump TDS packets

# Docker build and run
docker build -t tdsproxy .
docker run -p 1435:1435 tdsproxy
```

## Architecture Overview

TDSProxy is a proxy server for the MS SQL Server TDS (Tabular Data Stream) Protocol. It sits between SQL clients and SQL Server, handling TLS termination and authentication.

### Project Structure

- **TDSProxy** - Main executable. Hosts the proxy service and manages connections.
- **TDSProtocol** - Core library implementing TDS protocol parsing/serialization.
- **TDSProxy.Authentication** - Authentication interface for plugin-based authenticators (uses MEF).
- **SampleAuthenticator** - Example authenticator implementation.
- **TDSProtocolTests** - Unit tests for protocol handling.
- **TestConnection** - Test utility for SQL connections.

### Connection Flow

1. **TDSProxyService** (`TDSProxyService.cs`) - Hosted service that starts listeners based on `appsettings.json`
2. **TDSListener** (`TDSListener.cs`) - TCP listener that accepts connections and creates TDSConnection instances
3. **TDSConnection** (`TDSConnection.cs`) - Handles the full connection lifecycle:
   - PreLogin message exchange with client and server
   - SSL/TLS handshake with client (via `TdsSslHandshakeAdapter` inner class)
   - Optional TLS to backend SQL Server
   - Login7 authentication with pluggable authenticators
   - Bidirectional packet forwarding after login

### TDS Protocol Layer

The `TDSProtocol` library handles packet and message parsing:

- **TDSPacket** - Low-level packet with 8-byte header (type, status, length, SPID, packet ID, window)
- **TDSMessage** - Base class for messages, auto-registers concrete types via reflection
- **TDSPreLoginMessage** - Handles encryption negotiation
- **TDSLogin7Message** - SQL Server authentication with username/password
- **TDSTabularDataMessage** - Token-based messages (results, errors, etc.)
- **SMPPacket** - Session Multiplexing Protocol packets (MARS support)

### Configuration

Configuration is in `appsettings.json` with the structure defined in `TdsProxySection.cs`:

- `Listeners[]` - Array of listener configs (Host, Port, Tls settings)
- `Servers[]` - Array of backend SQL Server configs (Host, Port, Tls settings)

Each listener is paired with a server config by index.

### Authentication Plugin System

Authenticators implement `IAuthenticator` and are loaded via MEF. The `Authenticate` method receives client IP, username, password, database and returns an `AuthenticationResult` that can remap credentials for the backend server.

If no authenticators are configured, credentials pass through unchanged.

### TLS Handling

- Client-side TLS: Proxy presents its own certificate to clients
- Server-side TLS: Configurable per-server with `ValidateCertificate` and `TrustServerCertificate` options
- Supports TLS 1.0-1.3 for legacy SQL Server compatibility (Docker image configured for TLS 1.0)
