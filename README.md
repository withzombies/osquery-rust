# osquery-rust

By providing Rust bindings for Osquery this crate facilitates the implementation of Osquery extensions.

## Features

- ✅ **Table plugins** - Create custom tables to query system information
- ✅ **Logger plugins** - Implement custom logging backends for osquery
- ✅ **Writable tables** - Support for INSERT, UPDATE, and DELETE operations
- 🦀 **Pure Rust** - No C/C++ dependencies, just safe Rust code
- 🚀 **High performance** - Minimal overhead for extensions
- 📦 **Easy to use** - Simple API with examples to get started quickly

## Building

Clone the repository and build the workspace:

```bash
git clone https://github.com/polarlabs/osquery-rust.git
cd osquery-rust
cargo build --workspace
```

Run tests:

```bash
cargo test --workspace
```

The project uses a workspace structure with the main library and several examples. All examples are built automatically when you build the workspace.

## Quick Start

Here's a simple example of creating a table plugin that reports system uptime:

```rust
use osquery_rust::prelude::*;

#[derive(Default)]
struct UptimeTable;

impl ReadOnlyTable for UptimeTable {
    fn name(&self) -> &str {
        "uptime"
    }

    fn columns(&self) -> Vec<ColumnDef> {
        vec![
            ColumnDef::new("days", ColumnType::Integer),
            ColumnDef::new("hours", ColumnType::Integer),
            ColumnDef::new("minutes", ColumnType::Integer),
            ColumnDef::new("seconds", ColumnType::Integer),
        ]
    }

    fn generate(&self, _constraints: &QueryConstraints) -> Result<Vec<Row>, String> {
        let uptime_seconds = std::fs::read_to_string("/proc/uptime")
            .map_err(|e| e.to_string())?
            .split_whitespace()
            .next()
            .ok_or("Failed to parse uptime")?
            .parse::<f64>()
            .map_err(|e| e.to_string())? as u64;

        let days = uptime_seconds / 86400;
        let hours = (uptime_seconds % 86400) / 3600;
        let minutes = (uptime_seconds % 3600) / 60;
        let seconds = uptime_seconds % 60;

        Ok(vec![Row::from_iter([
            ("days", days.to_string()),
            ("hours", hours.to_string()),
            ("minutes", minutes.to_string()),
            ("seconds", seconds.to_string()),
        ])])
    }
}

fn main() {
    let mut server = Server::new(None, "/path/to/osquery/socket").unwrap();
    server.register_plugin(Plugin::table(UptimeTable::default()));
    server.run().unwrap();
}
```

## Usage Guide

### Creating Table Plugins

Table plugins allow you to expose data as SQL tables in osquery. There are two types:

1. **Read-only tables** - Implement the `ReadOnlyTable` trait
2. **Writable tables** - Implement the `Table` trait for full CRUD operations

See the [examples](examples/) directory for complete implementations.

### Creating Logger Plugins

Logger plugins receive log data from osquery and can forward it to various backends:

```rust
use osquery_rust::plugin::{LoggerPlugin, LogStatus};

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
}
```

### Integration with osquery

There are three ways to run your extension:

1. **Direct loading**: `osqueryi --extension /path/to/extension`
2. **Socket connection**: Run extension separately with `--socket /path/to/osquery.sock`
3. **Auto-loading**: Place extension in osquery's autoload directory

See the [examples README](examples/README.md) for detailed integration instructions.

## Examples

The repository includes several complete examples:

- **[table-proc-meminfo](examples/table-proc-meminfo/)** - Exposes `/proc/meminfo` as a queryable table
- **[writeable-table](examples/writeable-table/)** - Demonstrates INSERT, UPDATE, DELETE operations
- **[two-tables](examples/two-tables/)** - Shows how to register multiple tables in one extension
- **[logger-file](examples/logger-file/)** - Logger plugin that writes to files
- **[logger-syslog](examples/logger-syslog/)** - Logger plugin that sends logs to syslog

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

Please report issues on [GitHub](https://github.com/polarlabs/osquery-rust/issues) with:
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

## Additional Resources

- Tutorial: [osquery-rust tutorial](https://github.com/withzombies/osquery-rust/tree/main/tutorial)
- Examples: [osquery-rust by example](https://github.com/withzombies/osquery-rust/tree/main/examples)
- Documentation: [docs.rs/osquery-rust](https://docs.rs/osquery-rust)

## Related Projects

This project contributed the support for Unix Domain Sockets to [Apache Thrift's Rust crate](https://issues.apache.org/jira/browse/THRIFT-5283).

## Links

- [Osquery's GitHub repo](https://github.com/osquery/osquery)
- [Osquery documentation](https://osquery.readthedocs.io/)
- [Developing Osquery Extensions](https://osquery.readthedocs.io/en/stable/deployment/extensions/)
- [The Osquery SDK](https://osquery.readthedocs.io/en/stable/development/osquery-sdk/)