# graphoper

Passive GraphQL reconnaissance tool. Launches a Chromium browser, observes all network traffic during normal browsing, captures GraphQL operations and responses, downloads JS bundles, extracts embedded queries, and deduplicates everything.

## Install

```bash
go build -o graphoper .
```

Requires Chromium/Chrome installed on the system.

## Usage

```bash
# Browse a target — opens visible browser window
./graphoper https://target.example.com

# Headless mode
./graphoper -headless https://target.example.com

# Persist browser session (cookies, login state)
./graphoper -profile ./profile https://target.example.com

# Route through a proxy
./graphoper -proxy http://127.0.0.1:8080 https://target.example.com

# Custom bundle path
./graphoper -bundles ./mybundles https://target.example.com

# Project-scoped output (bundles, logs, exports)
./graphoper -project bugbounty-target https://target.example.com

# Export captured data on shutdown
./graphoper -project bugbounty-target -export https://target.example.com

# Set a session timeout
./graphoper -timeout 30m https://target.example.com

# Verbose logging
./graphoper -v https://target.example.com
```

## What It Captures

| Source | Data |
|--------|------|
| Network requests | GraphQL queries, mutations, operation names, variables, endpoints |
| Network responses | Response JSON, HTTP status, headers |
| JS bundles | Embedded queries from gql tags, Relay artifacts, Apollo documents |
| Response schema | `__typename` values, field names, nested object structure |

## Directory Structure

```
graphoper/
├── bundles/      # Downloaded JS bundles
├── exports/      # Optional export output (`-export`)
└── logs/         # Session logs
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-headless` | `false` | Run Chromium without a visible window |
| `-profile` | `""` | Browser profile directory for session persistence |
| `-proxy` | `""` | HTTP proxy URL |
| `-project` | `""` | Project name for per-project storage layout (`projects/<name>/...`) |
| `-bundles` | `bundles` | JS bundle download directory |
| `-export` | `false` | Export captured operations, responses, and schema fragments on shutdown |
| `-export-dir` | `exports` | Directory for export files (`.json` + `.graphql`) |
| `-timeout` | `0` (unlimited) | Maximum session duration |
| `-v` | `false` | Verbose logging |

## License

Private.
