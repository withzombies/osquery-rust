# Config File Plugin Example

This example demonstrates how to create a configuration plugin for osquery using osquery-rust. Config plugins provide osquery with its configuration data from various sources.

## Overview

This plugin reads configuration from JSON files on disk:
- Main configuration from a specified file (default: `/etc/osquery/osquery.conf`)
- Pack configurations from a directory (default: `/etc/osquery/packs/`)

## Config Plugin API

Config plugins in osquery handle two specific actions:

1. **genConfig**: Returns the main configuration as a JSON string
2. **genPack**: Returns a specific pack configuration by name

## Building

From the workspace root:

```bash
cargo build --example config-file
```

## Usage

### Option 1: Direct Extension Loading

```bash
# Build and create the .ext file
cargo build -p config-file
cp target/debug/config_file target/debug/config-file.ext

# Start osqueryi with the extension
osqueryi --extension target/debug/config-file.ext

# In another terminal, you can test the config plugin:
osqueryi "SELECT * FROM osquery_extensions WHERE name = 'file_config';"
```

### Option 1b: Extension Autoload

```bash
# Copy the extension to osquery's autoload directory
sudo cp target/debug/config-file.ext /etc/osquery/extensions/

# Start osqueryd with config specifying the plugin
sudo osqueryd --config_path /etc/osquery/osquery.conf --config_plugin file_config
```

### Option 2: Socket Connection

Terminal 1 - Start osqueryi:
```bash
osqueryi
```

In osqueryi, find the socket path:
```sql
SELECT path AS socket FROM osquery_extensions WHERE uuid = 0;
```

Terminal 2 - Run the extension:
```bash
target/debug/examples/config-file --socket /path/to/socket --config /path/to/config.json
```

## Command-line Options

- `--socket <PATH>`: Path to osquery socket (required)
- `-c, --config <PATH>`: Path to configuration file (default: `/etc/osquery/osquery.conf`)
- `-p, --packs <PATH>`: Path to packs directory (default: `/etc/osquery/packs`)
- `--interval <SECONDS>`: Delay between connectivity checks (default: 30)
- `--timeout <SECONDS>`: Connection timeout for autoloaded extensions (default: 30)
- `--verbose`: Enable verbose informational messages (default: true)

## Example Configuration Files

### Main Config (`/etc/osquery/osquery.conf`)
```json
{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10
  },
  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
      "interval": 3600
    }
  },
  "packs": {
    "osquery-monitoring": "/etc/osquery/packs/osquery-monitoring.json"
  }
}
```

### Pack File (`/etc/osquery/packs/osquery-monitoring.json`)
```json
{
  "queries": {
    "schedule": {
      "query": "SELECT name, interval, executions, output_size, wall_time FROM osquery_schedule;",
      "interval": 600
    }
  }
}
```

## Security Notes

- The plugin validates all JSON files before returning them
- Pack names are sanitized to prevent path traversal attacks
- File read errors are properly handled and reported

## How It Works

1. When osquery requests configuration (`action: genConfig`), the plugin reads the main config file and returns it
2. When osquery requests a pack (`action: genPack`), the plugin looks for `<pack_name>.json` in the packs directory
3. All files are validated as proper JSON before being returned
4. Errors are returned with descriptive messages for debugging