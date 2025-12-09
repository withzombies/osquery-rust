# Adversarial Test Coverage Review: osquery-rust

## Executive Summary

**Overall Grade: C+ (Needs Work)**

The test suite has a solid foundation with real osquery integration tests, but has significant gaps in verifying callback invocation for logger and config plugins. The 87% line coverage is misleading - many tests verify registration without verifying osquery actually uses the plugins.

---

## Findings by Category

### 1. Are Integration Tests Actually Running osquery?

**Verdict: YES - Real osquery is used**

Evidence:
- `integration_test.rs:43-94` - `get_osquery_socket()` waits for real Unix socket
- `pre-commit:104-116` - Starts real `osqueryd` with `--extensions_socket`
- CI workflow `integration.yml:44-73` - Installs and runs real osquery
- Tests panic if socket isn't available (line 81-89)

**Positive:** `test_table_plugin_end_to_end` (lines 236-322) actually:
1. Registers a table plugin
2. Queries it via osquery: `SELECT * FROM test_e2e_table`
3. Verifies returned data: `id=42, name=test_value`

This is genuine end-to-end testing.

---

### 2. Logger Plugin Coverage

**Verdict: CRITICAL GAP - Callbacks not verified**

| Test | What it tests | What it claims |
|------|---------------|----------------|
| `test_logger_plugin_receives_logs` | Registration only | "callback infrastructure verified" |
| `test_autoloaded_logger_receives_init` | Only `init()` callback | N/A |

**Problem at `integration_test.rs:414-427`:**
```rust
let string_logs = log_string_count.load(Ordering::SeqCst);
let status_logs = log_status_count.load(Ordering::SeqCst);
// Note: osqueryi typically doesn't generate many log events
// The main verification is that the logger plugin registered successfully
eprintln!("SUCCESS: Logger plugin registered and callback infrastructure verified");
```

**NO ASSERTION that logs were actually received!** The test passes whether `string_logs` is 0 or 1000.

**What could go wrong in production:**
- Logger plugin registers but never receives logs
- osquery doesn't route logs to extension plugins correctly
- Log format incompatibilities silently fail

**Severity: CRITICAL**

---

### 3. Config Plugin Coverage

**Verdict: CRITICAL GAP - gen_config() never invoked by osquery**

Evidence from `integration_test.rs:324-327`:
```rust
// Note: Config plugin integration testing requires autoload configuration.
// Runtime-registered config plugins are not used by osquery automatically.
// To test config plugins, build a config extension, autoload it, and configure
// osqueryd with --config_plugin=<your_plugin_name>.
```

**But no such test exists!**

The `coverage.sh:66-86` function `test_plugin_example` only verifies registration:
```bash
output=$(osqueryi --extension "./target/debug/$binary" \
    --line "SELECT name FROM osquery_extensions WHERE name = '$expected_name';")
```

This proves the extension registered, NOT that osquery called `gen_config()`.

**What could go wrong in production:**
- Config plugin registers but osquery never fetches config from it
- `gen_config()` returns data in wrong format, osquery silently ignores it
- Packs never get loaded via `gen_pack()`

**Severity: CRITICAL**

---

### 4. Table Plugin Coverage

**Verdict: GOOD - Actual queries verified**

The `test_table_plugin_end_to_end` test (lines 236-322) and `coverage.sh:40-62` (`test_table_example`) actually query tables and verify results.

From `coverage.sh:49-54`:
```bash
output=$(osqueryi --extension "./target/debug/$binary" \
    --line "SELECT * FROM $table LIMIT 1;")
if [ -n "$output" ] && ! echo "$output" | grep -q "no such table"; then
```

This is correct - it verifies osquery can query the table and get data.

**Severity: None for table plugins specifically**

---

### 5. Autoload vs Runtime Registration

**Verdict: PARTIAL - Only logger autoload tested**

| Plugin Type | Autoload Test | Runtime Test |
|-------------|---------------|--------------|
| Table | No | Yes (`test_table_plugin_end_to_end`) |
| Logger | Yes (`test_autoloaded_logger_receives_init`) | No (registration only) |
| Config | No | No (registration only) |

**What could go wrong in production:**
- Autoloaded table extensions might behave differently than runtime-registered
- Config extensions REQUIRE autoload to function, but autoload is untested
- Different extension timeout behaviors in autoload vs runtime

**Severity: HIGH**

---

### 6. Negative Testing

**Verdict: MINIMAL - Happy path only**

| Scenario | Tested? |
|----------|---------|
| Plugin returns error from `generate()` | No |
| Plugin panics during callback | No |
| Plugin timeout (slow response) | No |
| osquery disconnects mid-query | No |
| Invalid thrift response | No |
| Socket permission errors | No |
| Plugin returns malformed data | No |

**Example tests do test some error paths:**
- `config-file/src/main.rs:141-148` - Missing file handling
- `config-file/src/main.rs:200-215` - Path traversal attacks
- `writeable-table/src/main.rs:261-268` - Invalid update format

But integration tests have no failure scenarios.

**What could go wrong in production:**
- Silent data corruption when plugins return errors
- osquery hangs waiting for slow plugins
- No graceful degradation when plugins fail

**Severity: HIGH**

---

### 7. Example Plugin Unit Tests

| Example | Tests | Quality |
|---------|-------|---------|
| logger-file | 15 tests | **Good** - Tests all LoggerPlugin methods |
| config-file | 9 tests | **Good** - Includes security tests |
| config-static | 4 tests | Basic |
| writeable-table | 13 tests | **Good** - Full CRUD coverage |
| two-tables | 3 tests | **Weak** - Just name/columns/generate |
| logger-syslog | 12 tests | **Misleading** - Only tests facility parsing |
| table-proc-meminfo | 0 tests | **Missing** |

**Severity: MEDIUM**

---

### 8. Coverage Numbers Analysis

The 87% line coverage is inflated because:

1. **Executing code != testing behavior** - `test_logger_plugin_receives_logs` executes log callback registration code but doesn't verify it works

2. **Mock tests count toward coverage** - `server_tests.rs` uses `MockOsqueryClient` which tests server infrastructure, not osquery integration

3. **Auto-generated code excluded** - Good! `--ignore-filename-regex "_osquery"` correctly excludes thrift bindings

4. **Example tests are comprehensive for methods** - But they test in isolation, not through osquery

**Severity: MEDIUM** - Coverage number is not a lie, but it overstates confidence

---

## Specific "Faked" Tests

### 1. `test_logger_plugin_receives_logs`
**Location:** `integration_test.rs:330-427`
**Problem:** Counts logs but never asserts count > 0
**Fix:** Add assertion: `assert!(string_logs > 0 || status_logs > 0, "Logger should receive at least one log event");`

### 2. `test_plugin_example` in coverage.sh
**Location:** `coverage.sh:66-86`
**Problem:** Only verifies extension appears in `osquery_extensions` table
**Fix:** For config plugins, query with `--config_plugin=<name>` and verify config is used

### 3. `test_new_with_local_syslog`
**Location:** `logger-syslog/src/main.rs:273-278`
```rust
let result = SyslogLoggerPlugin::new(Facility::LOG_USER, None);
// We just verify it returns a result (success or error depending on system)
let _ = result;  // <- No assertion!
```
**Problem:** Result is discarded without checking
**Fix:** At minimum, verify it's `Ok` or `Err` based on platform

---

## Recommended Tests to Add

### CRITICAL Priority

1. **Config plugin autoload integration test**
   ```rust
   #[test]
   fn test_autoloaded_config_plugin_provides_config() {
       // Start osqueryd with --config_plugin=<test_plugin>
       // Query osquery_info to verify config loaded
       // Check osquery_flags shows correct options
   }
   ```

2. **Logger callback verification**
   ```rust
   #[test]
   fn test_logger_receives_query_logs() {
       // Register logger plugin
       // Execute query that generates logs (e.g., invalid SQL)
       // Assert log_string_count > 0 OR log_status_count > 0
   }
   ```

3. **Config gen_config invocation test**
   ```rust
   #[test]
   fn test_config_gen_config_called_on_startup() {
       // Track gen_config call count
       // Start osqueryd with --config_plugin=<test>
       // Assert gen_config was called at least once
   }
   ```

### HIGH Priority

4. **Plugin error handling**
   ```rust
   #[test]
   fn test_table_generate_error_propagates() {
       // Create table that returns error
       // Query it
       // Verify osquery reports error gracefully
   }
   ```

5. **table-proc-meminfo unit tests**
   ```rust
   #[test]
   fn test_proc_meminfo_parses_valid_file() { ... }
   #[test]
   fn test_proc_meminfo_handles_missing_file() { ... }
   ```

6. **Autoload table plugin test**
   ```rust
   #[test]
   fn test_autoloaded_table_works() {
       // Test that autoloaded tables behave same as runtime-registered
   }
   ```

### MEDIUM Priority

7. **Plugin timeout behavior**
8. **Socket reconnection after osquery restart**
9. **Multiple concurrent queries to same table**
10. **gen_pack() invocation test for config plugins**

---

## Summary Table

| Area | Status | Severity |
|------|--------|----------|
| Table plugins | Working | - |
| Logger plugin registration | Working | - |
| Logger plugin callbacks | Not verified | **CRITICAL** |
| Config plugin registration | Working | - |
| Config plugin gen_config | Not verified | **CRITICAL** |
| Autoload (logger) | init() only | HIGH |
| Autoload (config) | Missing | **CRITICAL** |
| Autoload (table) | Missing | HIGH |
| Error handling | Minimal | HIGH |
| Example tests | Variable | MEDIUM |
| Coverage accuracy | Overstated | MEDIUM |

---

## Final Assessment

**Grade: C+ (Needs Work)**

The test suite demonstrates competent testing infrastructure and real osquery integration for table plugins. However, the logger and config plugin testing has critical gaps where tests verify registration without verifying osquery actually uses the plugins. The comment "Logger plugin registered and callback infrastructure verified" when callbacks are never asserted is particularly concerning - it suggests the author knew the test was incomplete but claimed success anyway.

**To reach grade B:** Add config plugin autoload test, fix logger callback assertions
**To reach grade A:** Add comprehensive negative testing, timeout handling, and plugin error propagation tests

---

*Review conducted: 2025-12-09*
*Reviewer: Principal SRE adversarial review*
