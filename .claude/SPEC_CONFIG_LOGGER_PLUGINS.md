# Specification for Adding Configuration and Logging Plugin Support to osquery-rust

## Overview
This specification outlines the design for adding configuration and logging plugin support to osquery-rust, following the existing patterns established for table plugins while providing ergonomic APIs for Rust developers.

## Design Goals
1. **Consistency**: Follow the existing architecture patterns from table plugins
2. **Ergonomics**: Provide simple, type-safe Rust APIs that hide Thrift complexity
3. **Safety**: Maintain the no-panic, no-unwrap policy with proper error handling
4. **Flexibility**: Support both simple and complex use cases

## Configuration Plugin Design

### Trait Definition
```rust
// In src/plugin/config/mod.rs
pub trait ConfigPlugin: Send + Sync + 'static {
    fn name(&self) -> String;
    
    /// Generate configuration data
    /// Returns a map of config source names to JSON-encoded configuration strings
    fn gen_config(&self) -> Result<HashMap<String, String>, String>;
    
    /// Optional: Generate pack configuration
    /// Called when pack content is not provided inline
    fn gen_pack(&self, name: &str, value: &str) -> Result<String, String> {
        Err("Pack generation not implemented".to_string())
    }
    
    fn shutdown(&self) {}
}
```

### Implementation Structure
1. Create `src/plugin/config/` directory
2. Add wrapper type `ConfigPluginWrapper` that implements `OsqueryPlugin`
3. Handle the "action": "genConfig" request in the `generate()` method
4. Support "action": "genPack" for pack retrieval

### Example Usage
```rust
struct FileConfigPlugin {
    config_path: String,
}

impl ConfigPlugin for FileConfigPlugin {
    fn name(&self) -> String {
        "file_config".to_string()
    }
    
    fn gen_config(&self) -> Result<HashMap<String, String>, String> {
        let content = std::fs::read_to_string(&self.config_path)
            .map_err(|e| e.to_string())?;
        
        let mut config = HashMap::new();
        config.insert("main".to_string(), content);
        Ok(config)
    }
}
```

## Logging Plugin Design

### Trait Definition
```rust
// In src/plugin/logger/mod.rs
pub trait LoggerPlugin: Send + Sync + 'static {
    fn name(&self) -> String;
    
    /// Log a string message
    fn log_string(&self, message: &str) -> Result<(), String>;
    
    /// Log status information
    fn log_status(&self, status: &LogStatus) -> Result<(), String> {
        // Default implementation converts to string
        self.log_string(&status.to_string())
    }
    
    /// Log a snapshot (periodic state dump)
    fn log_snapshot(&self, snapshot: &str) -> Result<(), String> {
        self.log_string(snapshot)
    }
    
    fn init(&self) -> Result<(), String> {
        Ok(())
    }
    
    fn shutdown(&self) {}
}

pub struct LogStatus {
    pub severity: LogSeverity,
    pub filename: String,
    pub line: u32,
    pub message: String,
}

pub enum LogSeverity {
    Info,
    Warning,
    Error,
}
```

### Implementation Structure
1. Create `src/plugin/logger/` directory
2. Add wrapper type `LoggerPluginWrapper` that implements `OsqueryPlugin`
3. Handle different context types in the request:
   - "string": Regular log message
   - "status": Status log with metadata
   - "snapshot": Periodic state dump
   - "init": Initialize the logger
   - "health": Health check

### Example Usage
```rust
struct FileLoggerPlugin {
    log_file: Mutex<File>,
}

impl LoggerPlugin for FileLoggerPlugin {
    fn name(&self) -> String {
        "file_logger".to_string()
    }
    
    fn log_string(&self, message: &str) -> Result<(), String> {
        let mut file = self.log_file.lock()
            .map_err(|e| e.to_string())?;
        writeln!(file, "{}", message)
            .map_err(|e| e.to_string())
    }
}
```

## Integration with Existing Architecture

### Plugin Enum Extension
Update `src/plugin/_enums/plugin.rs`:
```rust
pub enum Plugin {
    Config(ConfigPluginWrapper),
    Logger(LoggerPluginWrapper),
    Table(TablePlugin),
}

impl Plugin {
    pub fn config<C: ConfigPlugin + 'static>(c: C) -> Self {
        Plugin::Config(ConfigPluginWrapper::new(c))
    }
    
    pub fn logger<L: LoggerPlugin + 'static>(l: L) -> Self {
        Plugin::Logger(LoggerPluginWrapper::new(l))
    }
}
```

### Server Updates
The existing `Server` implementation should work with minimal changes since it already accepts generic `OsqueryPlugin` implementations.

### Usage Example
```rust
use osquery_rust_ng::prelude::*;
use osquery_rust_ng::plugin::{ConfigPlugin, LoggerPlugin};

fn main() {
    let args = Args::parse();
    
    let mut server = Server::new(Some("multi-plugin-extension"), &args.socket)
        .expect("Failed to create server");
    
    // Register config plugin
    server.register_plugin(Plugin::config(FileConfigPlugin {
        config_path: "/etc/osquery/osquery.conf".to_string(),
    }));
    
    // Register logger plugin
    server.register_plugin(Plugin::logger(SyslogLoggerPlugin::new()));
    
    // Register table plugin (existing functionality)
    server.register_plugin(Plugin::readonly_table(MyTable {}));
    
    server.run().expect("Failed to run server");
}
```

## Implementation Plan

### Phase 1: Config Plugin Support
1. Create config plugin module structure
2. Implement `ConfigPlugin` trait
3. Create `ConfigPluginWrapper` implementing `OsqueryPlugin`
4. Add config plugin factory methods to `Plugin` enum
5. Create example config plugin (filesystem-based)
6. Add tests

### Phase 2: Logger Plugin Support
1. Create logger plugin module structure
2. Implement `LoggerPlugin` trait with log types
3. Create `LoggerPluginWrapper` implementing `OsqueryPlugin`
4. Add logger plugin factory methods to `Plugin` enum
5. Create example logger plugins (file, syslog)
6. Add tests

### Phase 3: Documentation and Examples
1. Update CLAUDE.md with new plugin types
2. Create comprehensive examples showing:
   - Multi-plugin extensions
   - Config plugin pulling from HTTP endpoint
   - Logger plugin writing to different backends
3. Update README with new capabilities

## Testing Strategy
1. Unit tests for each plugin wrapper
2. Integration tests with mock Osquery communication
3. Example extensions that combine all plugin types
4. Performance tests for high-volume logging

## Future Considerations
1. Async support for I/O-heavy operations
2. Plugin composition helpers
3. Built-in plugins for common scenarios (HTTP config, cloud logging)
4. Metrics and monitoring integration

## Technical Details

### Config Plugin Request/Response Format

**genConfig Request:**
```json
{
  "action": "genConfig"
}
```

**genConfig Response:**
```json
[
  {
    "main": "{\"schedule\": {...}, \"options\": {...}}",
    "packs": "{...}"
  }
]
```

**genPack Request:**
```json
{
  "action": "genPack",
  "name": "pack_name",
  "value": "optional_context"
}
```

**genPack Response:**
```json
[
  {
    "pack": "{\"queries\": {...}}"
  }
]
```

### Logger Plugin Request/Response Format

**String Log Request:**
```json
{
  "string": "Log message to write"
}
```

**Status Log Request:**
```json
{
  "status": {
    "severity": "0",  // 0=info, 1=warning, 2=error
    "filename": "file.cpp",
    "line": "123",
    "message": "Status message"
  }
}
```

**Snapshot Request:**
```json
{
  "snapshot": "{\"key\": \"value\"}"
}
```

**Init Request:**
```json
{
  "init": "logger_name"
}
```

All logger responses follow the standard extension response format with status codes.

## Error Handling

Both config and logger plugins should:
1. Never panic or unwrap
2. Return descriptive error messages
3. Log errors appropriately
4. Handle missing or malformed requests gracefully
5. Implement timeouts for external operations

## Security Considerations

1. **Config Plugins:**
   - Validate JSON before returning
   - Sanitize file paths
   - Implement access controls for remote configs
   - Use HTTPS for network-based configs

2. **Logger Plugins:**
   - Sanitize log messages
   - Implement rate limiting
   - Rotate log files appropriately
   - Ensure proper file permissions

## Performance Considerations

1. **Config Plugins:**
   - Cache configurations when appropriate
   - Implement efficient JSON parsing
   - Use connection pooling for HTTP configs

2. **Logger Plugins:**
   - Buffer log writes
   - Implement async I/O where possible
   - Use efficient serialization
   - Consider batching for network loggers