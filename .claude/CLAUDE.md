# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

osquery-rust is a Rust library that provides bindings for creating Osquery extensions. It enables developers to extend Osquery's functionality using Rust with a focus on performance and security.

## Critical Guidelines for Claude Code

**⚠️ MANDATORY WORKFLOW AFTER ANY CHANGES:**
1. **ALWAYS run `.git/hooks/pre-commit` after making changes**
2. **NEVER ignore or bypass Git hook failures**
3. **Resolve ALL issues before proceeding**
4. **Prioritize code quality over quick fixes**

## Common Development Commands

### Building
```bash
# Build the entire workspace
cargo build

# Build release version
cargo build --release

# Build a specific example
cargo build --example table-proc-meminfo

# Build all workspace members
cargo build --workspace
```

### Testing
```bash
# Run all tests with all features
cargo test --all-features

# Run tests verbosely
cargo test --all-features --verbose
```

### Linting and Code Quality
```bash
# Run clippy (strict lints are enforced - all warnings denied)
cargo clippy --all-features

# Format code
cargo fmt

# Check formatting without applying changes
cargo fmt --check
```

### Running Examples
```bash
# Build and run an example extension
cargo run --example table-proc-meminfo

# With osqueryi (option 1 - direct)
osqueryi --extension target/debug/examples/table-proc-meminfo

# With osqueryi (option 2 - socket)
# Terminal 1:
osqueryi
# In osqueryi: SELECT path AS socket FROM osquery_extensions WHERE uuid = 0;

# Terminal 2:
target/debug/examples/table-proc-meminfo --socket $HOME/.osquery/shell.em
```

## Architecture Overview

### Core Library Structure

The osquery-rust library (`/osquery-rust/src/`) implements a trait-based plugin system:

1. **Thrift Communication Layer** (`src/_osquery/`)
   - Auto-generated bindings from `osquery.thrift`
   - Handles RPC communication with Osquery via Unix Domain Sockets
   - Internal module - not exposed to library users

2. **Plugin System** (`src/plugin/`)
   - **Base Trait**: `OsqueryPlugin` - foundation for all plugin types
   - **Table Plugins**: Main focus of v0.1.x
     - `ReadOnlyTable` trait - for read-only data sources
     - `Table` trait - supports insert/update/delete operations
   - **Enums**: `TablePlugin` uses `enum_dispatch` for performance
   - **Query Handling**: `QueryConstraints` manages SQL WHERE clauses

3. **Extension Server** (`src/server.rs`)
   - Manages plugin registration and lifecycle
   - Handles Thrift RPC server on Unix socket
   - Implements ping mechanism for health checks

4. **Client Communication** (`src/client.rs`)
   - Manages connection to Osquery daemon
   - Handles extension registration protocol

### Key Design Patterns

1. **Trait-Based Plugin Architecture**
   - Extensions implement specific traits (`ReadOnlyTable` or `Table`)
   - Server registers plugins and routes requests
   - Clean separation between interface and implementation

2. **Type Safety**
   - `ColumnDef` defines table schema with SQL types
   - Strong typing throughout the API
   - Compile-time verification of table structures

3. **Error Handling**
   - No unwrap/expect/panic allowed (enforced by clippy)
   - Result types used throughout
   - Graceful error propagation

### Workspace Organization

```
osquery-rust/                    # Workspace root
├── osquery-rust/               # Main library crate
├── examples/                   # Example extensions
│   ├── table-proc-meminfo/    # Linux /proc/meminfo parser
│   ├── writeable-table/       # CRUD operations demo
│   └── two-tables/            # Multiple table registration
└── docker/                    # Testing environments
```

## Important Development Notes

### Thrift Interface Updates
When updating the Osquery interface:
1. Get latest `osquery.thrift` from Osquery repository
2. Generate Rust code: `thrift -out src/_osquery --gen rs -r osquery.thrift`
3. Generated code goes in `src/_osquery/osquery.rs`

### Strict Clippy Configuration
The project enforces strict clippy lints including:
- No `unwrap()`, `expect()`, or `panic!()`
- No array indexing without bounds checking
- All warnings treated as errors
- Unsafe code is forbidden

### Platform Support
- Primary: Linux
- CI tested: Ubuntu, macOS
- Planned: Windows (v0.5.0)

### Extension Development Workflow
1. Implement table trait (`ReadOnlyTable` or `Table`)
2. Define columns with `ColumnDef`
3. Create `Server` instance and register plugins
4. Handle command-line args (socket path)
5. Run server's main loop

### Testing Extensions
Extensions can be tested by:
1. Direct integration: `osqueryi --extension path/to/extension`
2. Socket connection: Run osqueryi, then connect extension to socket
3. Production: Place in osquery's autoload directory
