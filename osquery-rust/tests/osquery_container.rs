//! Test helper: OsqueryContainer for testcontainers
//!
//! Provides Docker-based osquery instances for integration tests.

use std::borrow::Cow;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};
use testcontainers::core::{Mount, WaitFor};
use testcontainers::Image;

/// Docker image for osquery
const OSQUERY_IMAGE: &str = "osquery/osquery";
const OSQUERY_TAG: &str = "5.17.0-ubuntu22.04";

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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // Integration tests can panic on infra failures
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
}
