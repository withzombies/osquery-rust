# Syslog Logger Extension Example

This example demonstrates how to create a syslog-based logger plugin for osquery using osquery-rust.

## Features

- Logs all osquery log messages to syslog
- Supports local Unix syslog or remote UDP syslog servers
- Maps osquery log severity to syslog priorities
- Configurable syslog facility
- Handles logger initialization and shutdown gracefully

## Building

```bash
cargo build --example logger-syslog
```

## Running

### Local Syslog

```bash
cargo run --example logger-syslog -- --socket /path/to/osquery.sock --facility daemon
```

### Remote Syslog

```bash
cargo run --example logger-syslog -- --socket /path/to/osquery.sock --facility daemon --remote syslog.example.com:514
```

## Supported Facilities

- kern, user, mail, daemon, auth, syslog, lpr, news
- uucp, cron, authpriv, ftp
- local0 through local7

## Command Line Options

- `--socket` / `-s`: Path to the osquery extension socket (required)
- `--facility` / `-f`: Syslog facility to use (default: `daemon`)
- `--remote`: Remote syslog server address (optional, format: `host:port`)