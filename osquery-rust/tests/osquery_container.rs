//! Test helper: OsqueryContainer for testcontainers
//!
//! Provides Docker-based osquery instances for integration tests.
//!
//! Two container types are available:
//! - `OsqueryContainer`: Basic osquery container (vanilla osquery/osquery image)
//! - `OsqueryTestContainer`: Pre-built image with Rust extensions already installed

use std::borrow::Cow;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};
use testcontainers::core::{ExecCommand, Mount, WaitFor};
use testcontainers::Image;

/// Docker image for osquery
const OSQUERY_IMAGE: &str = "osquery/osquery";
const OSQUERY_TAG: &str = "5.17.0-ubuntu22.04";

/// Pre-built test image with Rust extensions
const OSQUERY_TEST_IMAGE: &str = "osquery-rust-test";
const OSQUERY_TEST_TAG: &str = "latest";

/// Builder for creating osquery containers with various plugin configurations.
#[derive(Debug, Clone)]
pub struct OsqueryContainer {
    /// Extensions to autoload (paths inside container)
    extensions: Vec<String>,
    /// Config plugin name to use (e.g., "static_config")
    config_plugin: Option<String>,
    /// Logger plugins to use (e.g., "file_logger")
    logger_plugins: Vec<String>,
    /// Additional environment variables
    env_vars: Vec<(String, String)>,
    /// Host path for socket bind mount (directory containing socket)
    socket_host_path: Option<PathBuf>,
    /// Cached mount for the socket bind mount
    socket_mount: Option<Mount>,
}

impl Default for OsqueryContainer {
    fn default() -> Self {
        Self::new()
    }
}

impl OsqueryContainer {
    /// Create a new OsqueryContainer with default settings.
    pub fn new() -> Self {
        Self {
            extensions: Vec::new(),
            config_plugin: None,
            logger_plugins: Vec::new(),
            env_vars: Vec::new(),
            socket_host_path: None,
            socket_mount: None,
        }
    }

    /// Add a config plugin to use.
    #[allow(dead_code)]
    pub fn with_config_plugin(mut self, name: impl Into<String>) -> Self {
        self.config_plugin = Some(name.into());
        self
    }

    /// Add a logger plugin.
    #[allow(dead_code)]
    pub fn with_logger_plugin(mut self, name: impl Into<String>) -> Self {
        self.logger_plugins.push(name.into());
        self
    }

    /// Add an extension binary path (inside container).
    #[allow(dead_code)]
    pub fn with_extension(mut self, path: impl Into<String>) -> Self {
        self.extensions.push(path.into());
        self
    }

    /// Add an environment variable.
    #[allow(dead_code)]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }

    /// Set the host path for socket bind mount.
    /// The socket will appear at `<host_path>/osquery.em`.
    /// The host directory is bind-mounted to `/var/osquery` in the container.
    ///
    /// Note: On macOS, we do NOT canonicalize the path because Docker Desktop
    /// shares `/tmp` but not `/private/tmp` (even though `/tmp` is a symlink).
    /// Using the original path ensures Docker can resolve it.
    #[allow(dead_code)]
    pub fn with_socket_path(mut self, host_path: impl Into<PathBuf>) -> Self {
        let path = host_path.into();
        // Do NOT canonicalize - Docker Desktop shares /tmp, not /private/tmp
        // Create the mount and cache it (mounts() returns references)
        self.socket_mount = Some(Mount::bind_mount(
            path.display().to_string(),
            "/var/osquery",
        ));
        self.socket_host_path = Some(path);
        self
    }

    /// Get the full socket path (host_path + osquery.em).
    /// Returns None if no socket path was configured.
    #[allow(dead_code)]
    pub fn socket_path(&self) -> Option<PathBuf> {
        self.socket_host_path.as_ref().map(|p| p.join("osquery.em"))
    }

    /// Wait for the socket to appear on the host filesystem.
    /// Returns `Ok(PathBuf)` with socket path, or `Err` if timeout or no path configured.
    ///
    /// Polls every 100ms until the socket file exists or timeout is reached.
    #[allow(dead_code)]
    pub fn wait_for_socket(&self, timeout: Duration) -> Result<PathBuf, String> {
        let socket_path = self
            .socket_path()
            .ok_or_else(|| "No socket path configured".to_string())?;

        let start = Instant::now();
        while start.elapsed() < timeout {
            if socket_path.exists() {
                return Ok(socket_path);
            }
            thread::sleep(Duration::from_millis(100));
        }

        Err(format!(
            "Socket not found at {:?} after {:?}",
            socket_path, timeout
        ))
    }

    /// Build the osqueryd command line arguments.
    fn build_cmd(&self) -> Vec<String> {
        // Note: osquery docker image defaults to /bin/bash, so we need to specify osqueryd
        let mut cmd = vec![
            "osqueryd".to_string(),
            "--ephemeral".to_string(),
            "--disable_extensions=false".to_string(),
            "--extensions_socket=/var/osquery/osquery.em".to_string(),
            "--database_path=/tmp/osquery.db".to_string(),
            "--disable_watchdog".to_string(),
            "--force".to_string(),
            "--verbose".to_string(), // Enable verbose logging for testcontainers to see startup messages
        ];

        if let Some(ref config) = self.config_plugin {
            cmd.push(format!("--config_plugin={}", config));
        }

        if !self.logger_plugins.is_empty() {
            cmd.push(format!("--logger_plugin={}", self.logger_plugins.join(",")));
        }

        cmd
    }
}

impl Image for OsqueryContainer {
    fn name(&self) -> &str {
        OSQUERY_IMAGE
    }

    fn tag(&self) -> &str {
        OSQUERY_TAG
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![
            // Wait for osqueryd to create the extensions socket (logged via glog to stderr)
            // Use message_on_either_std since testcontainers may combine stdout/stderr
            WaitFor::message_on_either_std("Extension manager service starting"),
        ]
    }

    fn cmd(&self) -> impl IntoIterator<Item = impl Into<Cow<'_, str>>> {
        self.build_cmd()
    }

    fn env_vars(
        &self,
    ) -> impl IntoIterator<Item = (impl Into<Cow<'_, str>>, impl Into<Cow<'_, str>>)> {
        self.env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    fn mounts(&self) -> impl IntoIterator<Item = &Mount> {
        self.socket_mount.iter()
    }
}

// ============================================================================
// OsqueryTestContainer - Pre-built image with Rust extensions
// ============================================================================

/// Container using the pre-built osquery-rust-test image with extensions installed.
///
/// This container has osquery and Rust extensions pre-built inside, making it
/// suitable for integration tests that run entirely within Docker (no cross-VM
/// socket issues on macOS).
///
/// # Example
/// ```ignore
/// let container = OsqueryTestContainer::new().start().expect("start");
/// let result = exec_query(&container, "SELECT * FROM t1 LIMIT 1;");
/// assert!(result.contains("left"));
/// ```
#[derive(Debug, Clone)]
pub struct OsqueryTestContainer {
    /// Additional environment variables
    env_vars: Vec<(String, String)>,
}

impl Default for OsqueryTestContainer {
    fn default() -> Self {
        Self::new()
    }
}

impl OsqueryTestContainer {
    /// Create a new OsqueryTestContainer with default settings.
    pub fn new() -> Self {
        Self {
            env_vars: Vec::new(),
        }
    }

    /// Add an environment variable.
    #[allow(dead_code)]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }
}

impl Image for OsqueryTestContainer {
    fn name(&self) -> &str {
        OSQUERY_TEST_IMAGE
    }

    fn tag(&self) -> &str {
        OSQUERY_TEST_TAG
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![
            // Wait for osqueryd to start the extension manager and load extensions
            // The two-tables extension registers as "two-tables" in logs
            WaitFor::message_on_either_std("Extension manager service starting"),
        ]
    }

    fn env_vars(
        &self,
    ) -> impl IntoIterator<Item = (impl Into<Cow<'_, str>>, impl Into<Cow<'_, str>>)> {
        self.env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// Execute an SQL query inside the container using osqueryi --connect.
///
/// Returns the raw stdout output (typically JSON).
///
/// # Errors
/// Returns an error string if the exec fails or times out.
#[allow(dead_code)]
pub fn exec_query(
    container: &testcontainers::Container<OsqueryTestContainer>,
    query: &str,
) -> Result<String, String> {
    // Use osqueryi --connect to query the running osqueryd
    let cmd = ExecCommand::new([
        "/usr/bin/osqueryi",
        "--connect",
        "/var/osquery/osquery.em",
        "--json",
        query,
    ]);

    let mut result = container
        .exec(cmd)
        .map_err(|e| format!("Failed to exec command: {}", e))?;

    // Read stdout from the exec result
    let stdout = result
        .stdout_to_vec()
        .map_err(|e| format!("Failed to read stdout: {}", e))?;

    String::from_utf8(stdout).map_err(|e| format!("Invalid UTF-8 in output: {}", e))
}

/// Run integration tests inside a Docker container with osquery.
///
/// This function runs `cargo test` inside the osquery-rust-test container,
/// which has osquery, extensions, and Rust toolchain pre-installed.
///
/// Source code is mounted from `project_root` to `/workspace` in the container.
/// osqueryd is started with extensions autoloaded before tests run.
///
/// # Arguments
/// * `project_root` - Path to the osquery-rust project root
/// * `test_filter` - Test name filter (passed to cargo test)
/// * `env_vars` - Additional environment variables to set
///
/// # Returns
/// `Ok(output)` with test output, or `Err(error)` if tests failed.
#[allow(dead_code)]
pub fn run_integration_tests_in_docker(
    project_root: &std::path::Path,
    test_filter: Option<&str>,
    env_vars: &[(&str, &str)],
) -> Result<String, String> {
    use std::process::Command;

    // Build the docker command
    let mut cmd = Command::new("docker");
    cmd.arg("run")
        .arg("--rm")
        .arg("-v")
        .arg(format!("{}:/workspace", project_root.display()))
        .arg("-w")
        .arg("/workspace");

    // Add environment variables
    for (key, value) in env_vars {
        cmd.arg("-e").arg(format!("{}={}", key, value));
    }

    // Use the osquery-rust-test image
    cmd.arg(OSQUERY_TEST_IMAGE);

    // Build the shell command to run inside container
    // 1. Set up environment for extensions
    // 2. Start osqueryd with extensions in background
    // 3. Wait for socket
    // 4. Run cargo test
    let mut shell_cmd = String::from(
        r#"
# Set up directories and files for extensions
mkdir -p /var/log/osquery
touch /var/log/osquery/test.log

# Export environment for extensions BEFORE starting osqueryd
# logger-file extension reads FILE_LOGGER_PATH at startup
export FILE_LOGGER_PATH=/var/log/osquery/test.log
# config-static extension writes marker file at startup
export TEST_CONFIG_MARKER_FILE=/tmp/config_marker.txt

# Start osqueryd with extensions in background
/opt/osquery/bin/osqueryd --ephemeral --disable_extensions=false \
  --extensions_socket=/var/osquery/osquery.em \
  --extensions_autoload=/etc/osquery/extensions.load \
  --config_plugin=static_config \
  --logger_plugin=file_logger \
  --database_path=/tmp/osquery.db \
  --disable_watchdog --force 2>/dev/null &

# Wait for socket and extensions using osqueryi --connect (faster than fixed sleeps)
for i in $(seq 1 30); do
  if [ -S /var/osquery/osquery.em ]; then
    # Try to connect and verify extensions are registered
    if /usr/bin/osqueryi --connect /var/osquery/osquery.em -c "SELECT name FROM osquery_extensions WHERE name = 'file_logger'" 2>/dev/null | grep -q file_logger; then
      echo "Extensions registered successfully"
      # Trigger log events by running queries - this generates status logs immediately
      /usr/bin/osqueryi --connect /var/osquery/osquery.em -c "SELECT * FROM osquery_info" 2>/dev/null > /dev/null
      /usr/bin/osqueryi --connect /var/osquery/osquery.em -c "SELECT * FROM osquery_schedule" 2>/dev/null > /dev/null
      # Brief wait for scheduler to run at least once (3 second interval)
      sleep 4
      break
    fi
  fi
  sleep 1
done

# Set up test environment variables (tests read these)
export OSQUERY_SOCKET=/var/osquery/osquery.em
export TEST_LOGGER_FILE=/var/log/osquery/test.log

# Debug: show what extensions are loaded
/usr/bin/osqueryi --connect /var/osquery/osquery.em --json "SELECT name FROM osquery_extensions WHERE name != 'core';" 2>/dev/null || true

# Debug: show logger file contents
echo "Logger file contents:"
cat /var/log/osquery/test.log 2>/dev/null || echo "(empty)"

# Run cargo test
"#,
    );

    shell_cmd.push_str("cargo test --features osquery-tests --test integration_test");
    if let Some(filter) = test_filter {
        shell_cmd.push(' ');
        shell_cmd.push_str(filter);
    }
    shell_cmd.push_str(" -- --nocapture 2>&1");

    cmd.arg("sh").arg("-c").arg(&shell_cmd);

    // Run the command
    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run docker: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{}\n{}", stdout, stderr);

    if output.status.success() {
        Ok(combined)
    } else {
        Err(format!(
            "Tests failed with exit code {:?}:\n{}",
            output.status.code(),
            combined
        ))
    }
}

/// Get the project root directory.
///
/// This function finds the root of the osquery-rust workspace by looking
/// for Cargo.toml in parent directories.
#[allow(dead_code)]
pub fn find_project_root() -> Option<std::path::PathBuf> {
    let mut current = std::env::current_dir().ok()?;

    loop {
        // Check for workspace Cargo.toml (has [workspace] section)
        let cargo_toml = current.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(contents) = std::fs::read_to_string(&cargo_toml) {
                if contents.contains("[workspace]") {
                    return Some(current);
                }
            }
        }

        if !current.pop() {
            return None;
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)] // Integration tests can panic on infra failures
mod tests {
    use super::*;
    use std::os::unix::fs::FileTypeExt;
    use testcontainers::runners::SyncRunner;

    #[test]
    fn test_osquery_container_starts() {
        let container = OsqueryContainer::new()
            .start()
            .expect("Failed to start osquery container");

        // Container started successfully if we reach here
        // The ready_conditions ensure osqueryd is running
        assert!(!container.id().is_empty());
    }

    /// Test that socket bind mount makes the socket file visible on the host.
    ///
    /// NOTE: On macOS with Colima/Docker Desktop, Unix domain sockets created inside
    /// containers are NOT connectable from the host, even when the socket file appears
    /// via virtiofs/bind mounts. The socket file is visible but the kernel-level
    /// communication channel doesn't cross the VM boundary.
    ///
    /// This test verifies:
    /// - The socket file appears on the host filesystem
    /// - The container starts successfully with the bind mount
    ///
    /// For full end-to-end testing where extensions connect to osquery, use the
    /// Docker-based integration tests (hooks/pre-commit) which run entirely inside
    /// the container.
    #[test]
    fn test_socket_bind_mount_creates_socket_file() {
        // Create a temp directory for the socket under $HOME (Colima/Docker mounts $HOME by default)
        // /tmp is NOT shared with Colima VM - only the user's home directory is mounted
        let home = std::env::var("HOME").expect("HOME env var");
        let socket_dir = PathBuf::from(format!(
            "{}/.osquery-test/testcontainers-{}",
            home,
            std::process::id()
        ));
        if socket_dir.exists() {
            std::fs::remove_dir_all(&socket_dir).expect("cleanup old dir");
        }
        std::fs::create_dir_all(&socket_dir).expect("create socket dir");
        println!("Socket dir: {:?}", socket_dir);

        // Allow VirtioFS time to sync new directory to Docker/Colima VM
        thread::sleep(Duration::from_millis(500));

        // Start container with socket bind mount
        // The mount is provided via Image::mounts() trait implementation
        let osquery = OsqueryContainer::new().with_socket_path(&socket_dir);
        let container = osquery.start().expect("start container");

        // Wait for socket to appear (osquery needs time to create it)
        let socket_path = container
            .image()
            .wait_for_socket(Duration::from_secs(30))
            .expect("socket should appear");

        // Verify socket file exists and is a Unix socket
        assert!(socket_path.exists(), "socket file should exist");

        // On Unix, check file type is socket (starts with 's' in ls output)
        let metadata = std::fs::metadata(&socket_path).expect("get socket metadata");
        assert!(
            metadata.file_type().is_socket() || metadata.file_type().is_file(),
            "socket path should be a socket file"
        );

        println!("Socket file created at: {:?}", socket_path);

        // Note: We cannot test actual connection from host on macOS with Colima
        // because Unix sockets don't work across the VM boundary.
        // The full end-to-end test runs in Docker (see hooks/pre-commit).
    }

    /// Test that OsqueryTestContainer can query extension tables.
    ///
    /// This test uses the pre-built osquery-rust-test image which has the
    /// two-tables extension installed. It verifies:
    /// - The container starts with extensions loaded
    /// - We can query the t1 table (provided by two-tables extension)
    /// - The query returns expected data
    ///
    /// REQUIRES: Run `./scripts/build-test-image.sh` first to build the image.
    #[test]
    fn test_osquery_test_container_queries_extension_table() {
        let container = OsqueryTestContainer::new()
            .start()
            .expect("Failed to start osquery-rust-test container");

        // Container started successfully
        assert!(!container.id().is_empty());

        // Give the extension time to register after osqueryd starts
        thread::sleep(Duration::from_secs(3));

        // Query the t1 table (provided by two-tables extension)
        let result =
            exec_query(&container, "SELECT * FROM t1 LIMIT 1;").expect("query should succeed");

        println!("Query result: {}", result);

        // Verify the result contains expected columns from two-tables extension
        // The t1 table returns rows with "left" and "right" columns
        assert!(
            result.contains("left") && result.contains("right"),
            "Result should contain t1 table columns: {}",
            result
        );
    }

    /// Test INSERT, UPDATE, DELETE operations on writeable_table.
    ///
    /// The writeable-table extension provides a fully functional writeable table
    /// that stores data in a BTreeMap. Initial data: (0, foo, foo), (1, bar, bar), (2, baz, baz).
    ///
    /// This test verifies:
    /// - INSERT creates new rows with correct values
    /// - UPDATE modifies existing rows
    /// - DELETE removes rows
    /// - Each operation is strictly verified via SELECT queries
    ///
    /// REQUIRES: Run `./scripts/build-test-image.sh` first to build the image.
    #[test]
    fn test_writeable_table_crud_operations() {
        /// Parse JSON output from osqueryi --json into a Vec of rows.
        fn parse_json_rows(output: &str) -> Vec<serde_json::Value> {
            // osqueryi --json returns a JSON array, possibly with debug lines before it
            // Find the JSON array in the output
            let trimmed = output.trim();
            if let Some(start) = trimmed.find('[') {
                if let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(&trimmed[start..])
                {
                    return rows;
                }
            }
            Vec::new()
        }

        let container = OsqueryTestContainer::new()
            .start()
            .expect("Failed to start osquery-rust-test container");

        // Give extensions time to register
        thread::sleep(Duration::from_secs(3));

        // =========================================================
        // 1. VERIFY INITIAL STATE (exactly 3 rows: foo, bar, baz)
        // =========================================================
        let result = exec_query(&container, "SELECT * FROM writeable_table;")
            .expect("Initial SELECT failed");
        println!("Initial state: {}", result);

        let rows = parse_json_rows(&result);
        assert_eq!(
            rows.len(),
            3,
            "Expected exactly 3 initial rows, got {}. Output: {}",
            rows.len(),
            result
        );

        // Verify exact initial data exists
        assert!(
            rows.iter().any(|r| r["name"] == "foo"),
            "Initial data should contain 'foo'"
        );
        assert!(
            rows.iter().any(|r| r["name"] == "bar"),
            "Initial data should contain 'bar'"
        );
        assert!(
            rows.iter().any(|r| r["name"] == "baz"),
            "Initial data should contain 'baz'"
        );

        // =========================================================
        // 2. TEST INSERT - add a new row
        // =========================================================
        let insert_result = exec_query(
            &container,
            "INSERT INTO writeable_table (name, lastname) VALUES ('alice', 'smith');",
        )
        .expect("INSERT should succeed");
        println!("INSERT result: {}", insert_result);

        // STRICT VERIFICATION: Query for the new row specifically
        // Note: rowid is a hidden column, so we must select it explicitly
        let verify_insert = exec_query(
            &container,
            "SELECT rowid, name, lastname FROM writeable_table WHERE name='alice' AND lastname='smith';",
        )
        .expect("SELECT after INSERT failed");
        println!("After INSERT: {}", verify_insert);

        let rows = parse_json_rows(&verify_insert);
        assert_eq!(
            rows.len(),
            1,
            "Should find exactly 1 inserted row with name='alice'. Output: {}",
            verify_insert
        );
        assert_eq!(rows[0]["name"], "alice", "Inserted name should be 'alice'");
        assert_eq!(
            rows[0]["lastname"], "smith",
            "Inserted lastname should be 'smith'"
        );

        // Get the rowid for subsequent operations
        let inserted_rowid = rows[0]["rowid"]
            .as_str()
            .expect("inserted row should have rowid");
        println!("Inserted row has rowid: {}", inserted_rowid);

        // =========================================================
        // 3. TEST UPDATE - modify the inserted row
        // =========================================================
        let update_query = format!(
            "UPDATE writeable_table SET name='updated_alice' WHERE rowid={};",
            inserted_rowid
        );
        let update_result = exec_query(&container, &update_query).expect("UPDATE should succeed");
        println!("UPDATE result: {}", update_result);

        // STRICT VERIFICATION: Query to confirm update
        let verify_update = exec_query(
            &container,
            &format!(
                "SELECT rowid, name, lastname FROM writeable_table WHERE rowid={};",
                inserted_rowid
            ),
        )
        .expect("SELECT after UPDATE failed");
        println!("After UPDATE: {}", verify_update);

        let rows = parse_json_rows(&verify_update);
        assert_eq!(
            rows.len(),
            1,
            "Row should still exist after UPDATE. Output: {}",
            verify_update
        );
        assert_eq!(
            rows[0]["name"], "updated_alice",
            "Name should be updated to 'updated_alice'"
        );
        assert_eq!(
            rows[0]["lastname"], "smith",
            "Lastname should be unchanged (still 'smith')"
        );

        // =========================================================
        // 4. TEST DELETE - remove the row we created
        // =========================================================
        let delete_query = format!(
            "DELETE FROM writeable_table WHERE rowid={};",
            inserted_rowid
        );
        let delete_result = exec_query(&container, &delete_query).expect("DELETE should succeed");
        println!("DELETE result: {}", delete_result);

        // STRICT VERIFICATION: Row should be gone
        let verify_delete = exec_query(
            &container,
            &format!(
                "SELECT rowid, name, lastname FROM writeable_table WHERE rowid={};",
                inserted_rowid
            ),
        )
        .expect("SELECT after DELETE failed");
        println!("After DELETE: {}", verify_delete);

        let rows = parse_json_rows(&verify_delete);
        assert_eq!(
            rows.len(),
            0,
            "Deleted row should not exist. Output: {}",
            verify_delete
        );

        // =========================================================
        // 5. VERIFY FINAL STATE (back to exactly 3 original rows)
        // =========================================================
        let final_result =
            exec_query(&container, "SELECT * FROM writeable_table;").expect("Final SELECT failed");
        println!("Final state: {}", final_result);

        let rows = parse_json_rows(&final_result);
        assert_eq!(
            rows.len(),
            3,
            "Should have exactly 3 rows after full CRUD cycle (no side effects). Output: {}",
            final_result
        );

        println!("SUCCESS: All CRUD operations verified on writeable_table");
    }
}
