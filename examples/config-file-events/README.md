# File Events Config Plugin Example

This example demonstrates a simple static configuration plugin that enables file event monitoring in osquery for the `/tmp` directory.

## Overview

This plugin provides a static configuration that:
- Enables file events monitoring (`enable_file_events: true`)
- Watches `/tmp` directory recursively for all file changes
- Creates a scheduled query to monitor the `file_events` table every 10 seconds
- Sets reasonable defaults for event retention and limits

## File Events in osquery

File events allow you to monitor file system changes in real-time. When enabled, osquery tracks:
- File creation
- File modification
- File deletion
- File moves/renames
- Attribute changes

## Building

From the workspace root:

```bash
cargo build -p config-file-events
```

## Usage

### Basic Usage

```bash
# Build and create the .ext file
cargo build -p config-file-events
cp target/debug/config_file_events target/debug/config-file-events.ext

# Start osqueryi with the extension
osqueryi --extension target/debug/config-file-events.ext --config_plugin file_events_config

# In osqueryi, query file events:
SELECT * FROM file_events;

# Create a test file to see events
echo "test" > /tmp/test.txt

# Query again to see the CREATE event
SELECT * FROM file_events WHERE target_path = '/tmp/test.txt';
```

## Command-line Options

- `--socket <PATH>`: Path to osquery socket (required)
- `--interval <SECONDS>`: Delay between connectivity checks (default: 30)
- `--timeout <SECONDS>`: Connection timeout for autoloaded extensions (default: 30)
- `--verbose`: Enable verbose informational messages

## Static Configuration

The plugin provides this static configuration:

```json
{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10,
    "enable_file_events": "true",
    "disable_events": "false",
    "events_expiry": "3600",
    "events_max": "50000"
  },
  "schedule": {
    "file_events": {
      "query": "SELECT * FROM file_events;",
      "interval": 10,
      "removed": false
    }
  },
  "file_paths": {
    "/tmp": ["%%"]
  }
}
```

## File Path Patterns

The `%%` pattern means "watch all files recursively" in the directory. You can also use specific patterns:
- `%.log` - Watch only .log files
- `%/%.txt` - Watch .txt files in immediate subdirectories

## Example Queries

Once file events are enabled, you can run queries like:

```sql
-- See all recent file events
SELECT * FROM file_events ORDER BY time DESC LIMIT 20;

-- Find files created in /tmp
SELECT * FROM file_events 
WHERE target_path LIKE '/tmp/%' 
  AND action = 'CREATED';

-- Monitor configuration file changes
SELECT * FROM file_events 
WHERE target_path LIKE '/etc/%' 
  AND action IN ('UPDATED', 'ATTRIBUTES_MODIFIED');

-- Track executable file creation
SELECT * FROM file_events 
WHERE target_path LIKE '%.exe' 
   OR target_path LIKE '%.sh'
   OR target_path LIKE '%.bin';
```

## Performance Considerations

- File events can generate significant data on busy systems
- Use specific paths rather than watching entire filesystems
- The `events_expiry` option (3600 seconds) controls how long events are retained
- The `events_max` option (50000) limits the number of events stored

## Security Use Cases

This configuration is particularly useful for:
- Detecting malware droppers in temporary directories
- Monitoring sensitive configuration file changes
- Tracking user downloads
- Auditing file access patterns
- Detecting unauthorized file modifications