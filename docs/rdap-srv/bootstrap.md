# RDAP Bootstrap Server

The RDAP server can be configured to operate as a bootstrap server using the `RDAP_SRV_BOOTSTRAP` environment variable. When enabled, the server automatically downloads IANA RDAP bootstrap files and provides HTTP redirects to direct clients to the appropriate authoritative RDAP services.

## Overview

A bootstrap server serves as a single entry point for RDAP queries. Instead of clients needing to know which RDAP server is authoritative for a specific resource, they can query the bootstrap server, which redirects them to the correct service.

## Configuration

Enable bootstrap functionality by setting the `RDAP_SRV_BOOTSTRAP` environment variable:

```bash
export RDAP_SRV_BOOTSTRAP=true
```

## Bootstrap Process

When bootstrap mode is enabled, the server performs the following operations:

### 1. Initial Bootstrap
- Downloads IANA RDAP bootstrap files from IANA
- Processes the bootstrap data for different resource types
- Creates redirect templates for all supported services
- Runs once before starting the bootstrap update thread

### 2. Automatic Updates
- Refreshes bootstrap data every 60 seconds
- Checks for updated IANA registry files
- Updates redirect templates when new data is available
- Maintains cached bootstrap files

### 3. Data Sources
The bootstrap server downloads and processes the following IANA registries:

- **DNS Bootstrap**: Domain name services (TLD delegations) and reverse DNS.
- **ASN Bootstrap**: Autonomous System number services  
- **IPv4 Bootstrap**: IPv4 network services including reverse DNS.
- **IPv6 Bootstrap**: IPv6 network services including reverse DNS.
- **Object Tags**: Service provider entity tags

## Redirect Behavior

The bootstrap server issues HTTP 307 (Temporary Redirect) responses for all queries, directing clients to the authoritative RDAP service for the requested resource.

### Resource Types

#### Domain Names
```http
GET /domain/example.com HTTP/1.1
Host: bootstrap.rdap.example.com

HTTP/1.1 307 Temporary Redirect
Location: https://registry.example.com/rdap/domain/example.com
```

#### IP Networks
```http
GET /ip/203.0.113.0/24 HTTP/1.1
Host: bootstrap.rdap.example.com

HTTP/1.1 307 Temporary Redirect  
Location: https://rir.example.com/rdap/ip/203.0.113.0/24
```

#### Autonomous Systems
```http
GET /autnum/64496 HTTP/1.1
Host: bootstrap.rdap.example.com

HTTP/1.1 307 Temporary Redirect
Location: https://rir3.example.com/rdap/autnum/64496
```

## Configuration Options

### Environment Variables

```bash
# Enable bootstrap functionality
export RDAP_SRV_BOOTSTRAP=true

# Optional: Update storage when bootstrap data changes
export RDAP_SRV_UPDATE_ON_BOOTSTRAP=true

# Required: Data directory for bootstrap files
export RDAP_SRV_DATA_DIR="/var/lib/rdap-srv/data"
```

### Update Behavior

The `RDAP_SRV_UPDATE_ON_BOOTSTRAP` variable controls how bootstrap updates are handled:

- **false (default)**: Triggers data reload without full storage update
- **true**: Performs complete storage update when bootstrap data changes

