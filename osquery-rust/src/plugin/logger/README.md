# Logger Plugin Support

This module implements logger plugin support for osquery-rust, allowing developers to create custom logging backends for osquery.

## Overview

Logger plugins in osquery handle all log output from the osquery daemon. This includes:
- Query results (via "string" context)
- Status logs (via "status" context)
- Snapshot logs (via "snapshot" context)
- Health checks (via "health" context)

## Implementation Details

Osquery communicates with logger plugins differently than table plugins. Instead of using a single `generate` method with an "action" parameter, logger plugins receive requests with context-specific keys:

- `{"string": "log message"}` - Regular log entries
- `{"status": "{\"severity\": \"0\", \"filename\": \"file.cpp\", \"line\": \"123\", \"message\": \"Status message\"}"}` - Status logs with metadata
- `{"snapshot": "json_data"}` - Periodic state snapshots
- `{"init": "logger_name"}` - Logger initialization
- `{"health": ""}` - Health check requests

## Usage

To create a logger plugin, implement the `LoggerPlugin` trait:

```rust
use osquery_rust::plugin::{LoggerPlugin, LogStatus, LogSeverity};

struct MyLogger;

impl LoggerPlugin for MyLogger {
    fn name(&self) -> String {
        "my_logger".to_string()
    }
    
    fn log_string(&self, message: &str) -> Result<(), String> {
        // Handle string log messages
        println!("LOG: {}", message);
        Ok(())
    }
    
    fn log_status(&self, status: &LogStatus) -> Result<(), String> {
        // Handle status logs with severity information
        println!("[{}] {}:{} - {}", 
            status.severity, 
            status.filename, 
            status.line, 
            status.message
        );
        Ok(())
    }
    
    fn log_snapshot(&self, snapshot: &str) -> Result<(), String> {
        // Handle periodic state dumps
        println!("SNAPSHOT: {}", snapshot);
        Ok(())
    }
}
```

## Registration

Register your logger plugin with the osquery extension server:

```rust
use osquery_rust::prelude::*;
use osquery_rust::plugin::Plugin;

fn main() {
    let mut server = Server::new(Some("my-extension"), "/path/to/socket")
        .expect("Failed to create server");
    
    server.register_plugin(Plugin::logger(MyLogger));
    
    server.run().expect("Failed to run server");
}
```

## Log Types

### String Logs
Basic text messages from osquery.

### Status Logs
Structured logs with severity levels:
- `Info` (0)
- `Warning` (1)
- `Error` (2)

### Snapshots
Periodic dumps of osquery's internal state, typically in JSON format.

## Examples

See the examples directory for complete implementations:
- `logger-file`: Logs to a file with timestamps
- `logger-syslog`: Logs to local or remote syslog

## Best Practices

1. **Error Handling**: Never panic in logger methods. Always return errors as `Result<(), String>`.
2. **Performance**: Logger plugins are called frequently. Keep operations fast and consider buffering.
3. **Thread Safety**: Your logger may be called from multiple threads. Use appropriate synchronization.
4. **Initialization**: Use the `init` method for one-time setup like opening files or network connections.
5. **Cleanup**: Implement proper cleanup in the `shutdown` method.