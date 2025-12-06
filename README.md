[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Status][test-action-image]][test-action-link]
[![Apache 2.0 Licensed][license-apache-image]][license-apache-link]
[![MIT Licensed][license-mit-image]][license-mit-link]

# osquery-rust-ng

By providing Rust bindings for Osquery this crate facilitates the implementation of Osquery extensions.

## Features

- ✅ **Table plugins** - Create custom tables to query system information
- ✅ **Logger plugins** - Implement custom logging backends for osquery
- ✅ **Config plugins** - Provide custom configuration sources for osquery
- ✅ **Writable tables** - Support for INSERT, UPDATE, and DELETE operations
- 🦀 **Pure Rust** - No C/C++ dependencies, just safe Rust code
- 🚀 **High performance** - Minimal overhead for extensions
- 📦 **Easy to use** - Simple API with examples to get started quickly

## Building

Clone the repository and build the workspace:

```bash
git clone https://github.com/withzombies/osquery-rust.git
cd osquery-rust
cargo build --workspace
```

Run tests:

```bash
cargo test --workspace
```

The project uses a workspace structure with the main library and several examples. All examples are built automatically when you build the workspace.

## Quick Start

Here's a simple example of creating a read-only table plugin:

```rust
use osquery_rust_ng::prelude::*;
use osquery_rust_ng::plugin::{ColumnDef, ColumnType, ColumnOptions, Plugin, ReadOnlyTable};
use std::collections::BTreeMap;

struct MyTable;

impl ReadOnlyTable for MyTable {
    fn name(&self) -> String {
        "my_table".to_string()
    }

    fn columns(&self) -> Vec<ColumnDef> {
        vec![
            ColumnDef::new("greeting", ColumnType::Text, ColumnOptions::DEFAULT),
            ColumnDef::new("count", ColumnType::Integer, ColumnOptions::DEFAULT),
        ]
    }

    fn generate(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
        let row = BTreeMap::from([
            ("greeting".to_string(), "Hello, osquery!".to_string()),
            ("count".to_string(), "42".to_string()),
        ]);
        ExtensionResponse::new(ExtensionStatus::default(), vec![row])
    }

    fn shutdown(&self) {
        // Called when the extension is shutting down
    }
}

fn main() -> std::io::Result<()> {
    let mut server = Server::new(None, "/path/to/osquery/socket")?;
    server.register_plugin(Plugin::readonly_table(MyTable));
    server.run().map_err(std::io::Error::other)
}
```

## Migrating to 2.0

Version 2.0 simplifies the shutdown API by removing `ShutdownReason`. If upgrading from 1.x:

**Before (1.x):**
```rust
fn shutdown(&self, reason: ShutdownReason) {
    println!("Shutting down: {reason}");
}
```

**After (2.0):**
```rust
fn shutdown(&self) {
    println!("Shutting down");
}
```

This affects all plugin traits: `ReadOnlyTable`, `Table`, `LoggerPlugin`, and `ConfigPlugin`.

The `Server::stop()` and `ServerStopHandle::stop()` methods also no longer take a reason parameter.

## Usage Guide

### Creating Table Plugins

Table plugins allow you to expose data as SQL tables in osquery. There are two types:

1. **Read-only tables** - Implement the `ReadOnlyTable` trait
2. **Writable tables** - Implement the `Table` trait for full CRUD operations

### Creating Logger Plugins

Logger plugins receive log data from osquery and can forward it to various backends:

```rust
use osquery_rust_ng::plugin::{LoggerPlugin, LogStatus, LoggerFeatures};

struct MyLogger;

impl LoggerPlugin for MyLogger {
    fn name(&self) -> String {
        "my_logger".to_string()
    }

    fn log_string(&self, message: &str) -> Result<(), String> {
        println!("Log: {}", message);
        Ok(())
    }

    fn log_status(&self, status: &LogStatus) -> Result<(), String> {
        println!("[{}] {}:{} - {}",
            status.severity, status.filename, status.line, status.message);
        Ok(())
    }

    // Advertise support for status logs (enabled by default)
    fn features(&self) -> i32 {
        LoggerFeatures::LOG_STATUS
    }
}
```

The `features()` method tells osquery what log types your plugin supports. By default, loggers receive status logs (INFO/WARNING/ERROR from osquery internals). Available features:

- `LoggerFeatures::BLANK` - Query results only
- `LoggerFeatures::LOG_STATUS` - Status logs (default)
- `LoggerFeatures::LOG_EVENT` - Event logs

### Creating Config Plugins

Config plugins provide configuration data to osquery, allowing dynamic configuration management:

```rust
use osquery_rust_ng::plugin::ConfigPlugin;
use std::collections::HashMap;

struct MyConfig;

impl ConfigPlugin for MyConfig {
    fn name(&self) -> String {
        "my_config".to_string()
    }

    fn gen_config(&self) -> Result<HashMap<String, String>, String> {
        let mut config_map = HashMap::new();
        
        // Provide JSON configuration
        let config = r#"{
            "options": {
                "host_identifier": "hostname",
                "schedule_splay_percent": 10
            },
            "schedule": {
                "heartbeat": {
                    "query": "SELECT version FROM osquery_info;",
                    "interval": 3600
                }
            }
        }"#;
        
        config_map.insert("main".to_string(), config.to_string());
        Ok(config_map)
    }

    fn gen_pack(&self, name: &str, _value: &str) -> Result<String, String> {
        // Optionally provide query packs
        Err(format!("Pack '{}' not found", name))
    }
}
```

### Integration with osquery

There are three ways to run your extension:

1. **Direct loading**: `osqueryi --extension /path/to/extension`
2. **Socket connection**: Run extension separately with `--socket /path/to/osquery.sock`
3. **Auto-loading**: Place extension in osquery's autoload directory

See the [examples](examples/) directory for complete implementations.

### Graceful Shutdown

Extensions support graceful shutdown through multiple mechanisms:

**Signal Handling (recommended for production)**

Use `run_with_signal_handling()` to automatically handle SIGTERM and SIGINT:

```rust
fn main() -> std::io::Result<()> {
    let mut server = Server::new(None, "/path/to/socket")?;
    server.register_plugin(Plugin::readonly_table(MyTable));

    // Handles SIGTERM (systemd) and SIGINT (Ctrl+C)
    server.run_with_signal_handling().map_err(std::io::Error::other)
}
```

**Programmatic Shutdown**

Use `ServerStopHandle` to stop the server from another thread:

```rust
let mut server = Server::new(None, "/path/to/socket")?;
let handle = server.get_stop_handle();

// In another thread or signal handler:
std::thread::spawn(move || {
    // ... wait for condition ...
    handle.stop();
});

server.run()?;
```

**Shutdown Lifecycle**

When shutdown is triggered (via signal, osquery RPC, or `stop()`):

1. The server deregisters from osquery
2. All plugins receive a `shutdown()` callback
3. The socket file is cleaned up
4. `run()` returns

## Examples

The repository includes several complete examples:

- **[table-proc-meminfo](examples/table-proc-meminfo/)** - Exposes `/proc/meminfo` as a queryable table
- **[writeable-table](examples/writeable-table/)** - Demonstrates INSERT, UPDATE, DELETE operations
- **[two-tables](examples/two-tables/)** - Shows how to register multiple tables in one extension
- **[logger-file](examples/logger-file/)** - Logger plugin that writes to files
- **[logger-syslog](examples/logger-syslog/)** - Logger plugin that sends logs to syslog
- **[config-file](examples/config-file/)** - Config plugin that loads configuration from JSON files
- **[config-static](examples/config-static/)** - Config plugin that provides static configuration

Each example includes its own README with specific build and usage instructions.

## Contributing

We welcome contributions! Here's how to get started:

### Development Setup

1. Fork and clone the repository
2. Install the pre-commit hook:
   ```bash
   cp .hooks/pre-commit .git/hooks/pre-commit
   chmod +x .git/hooks/pre-commit
   ```

### Code Quality Standards

This project maintains high code quality standards:

- All code must pass `cargo fmt`
- No clippy warnings allowed (enforced by CI)
- All tests must pass
- Unsafe code must be documented

The pre-commit hook automatically runs these checks.

### Testing

Run the full test suite:

```bash
cargo test --workspace
```

### Pull Request Process

1. Create a feature branch from `main`
2. Write tests for new functionality
3. Ensure all checks pass
4. Submit a PR with a clear description
5. Address review feedback

### Reporting Issues

Please report issues on [GitHub](https://github.com/withzombies/osquery-rust/issues) with:
- osquery version
- Rust version
- Operating system
- Steps to reproduce
- Expected vs actual behavior

## Project Structure

The project is organized as a Cargo workspace:

- **osquery-rust/** - The main library crate with Thrift bindings and plugin framework
- **examples/** - Working examples demonstrating different plugin types:
  - `table-proc-meminfo/` - Read-only table example
  - `writeable-table/` - Full CRUD table example
  - `two-tables/` - Multiple tables in one extension
  - `logger-file/` - File logger plugin
  - `logger-syslog/` - Syslog logger plugin
  - `config-file/` - An example that loads a config from a json file
  - `config-static/` - An example that provides a static config

## Additional Resources

- Examples: [osquery-rust by example](https://github.com/withzombies/osquery-rust/tree/main/examples)
- API Documentation: [docs.rs/osquery-rust-ng](https://docs.rs/osquery-rust-ng)

## Related Projects

This project contributed the support for Unix Domain Sockets to [Apache Thrift's Rust crate](https://issues.apache.org/jira/browse/THRIFT-5283).

This project was initially forked from [polarlab's osquery-rust project](https://github.com/polarlabs/osquery-rust).

## Links

- [Osquery's GitHub repo](https://github.com/osquery/osquery)
- [Osquery documentation](https://osquery.readthedocs.io/)
- [Developing Osquery Extensions](https://osquery.readthedocs.io/en/stable/deployment/extensions/)
- [The Osquery SDK](https://osquery.readthedocs.io/en/stable/development/osquery-sdk/)

[//]: # (links)

[crate-image]: https://img.shields.io/crates/v/osquery-rust-ng.svg

[crate-link]: https://crates.io/crates/osquery-rust-ng

[docs-image]: https://docs.rs/osquery-rust-ng/badge.svg

[docs-link]: https://docs.rs/osquery-rust-ng/

[test-action-image]: https://github.com/withzombies/osquery-rust/workflows/Rust%20CI/badge.svg

[test-action-link]: https://github.com/withzombies/osquery-rust/actions?query=workflow:Rust%20CI

[license-apache-image]: https://img.shields.io/badge/license-Apache2.0-blue.svg

[license-apache-link]: http://www.apache.org/licenses/LICENSE-2.0

[license-mit-image]: https://img.shields.io/badge/license-MIT-blue.svg

[license-mit-link]: http://www.apache.org/licenses/LICENSE-2.0
