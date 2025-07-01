# File Logger Extension Example

This example demonstrates how to create a file-based logger plugin for osquery using osquery-rust.

## Features

- Logs all osquery log messages to a file
- Supports different log types: string logs, status logs, and snapshots
- Timestamps all log entries
- Handles logger initialization and shutdown gracefully

## Building

```bash
cargo build --example logger-file
```

## Running

First, ensure osquery is running with extensions enabled:

```bash
osqueryi --extension /path/to/osquery.sock
```

Then run the logger extension:

```bash
cargo run --example logger-file -- --socket /path/to/osquery.sock --log-file /tmp/osquery.log
```

## Testing

In osqueryi, you can test the logger by:

1. Setting it as the active logger:
```sql
SELECT * FROM osquery_extensions;
```

2. Running queries that generate logs
3. Checking the log file specified with `--log-file`

## Command Line Options

- `--socket` / `-s`: Path to the osquery extension socket (required)
- `--log-file` / `-l`: Path to the log file (default: `/tmp/osquery-logger.log`)