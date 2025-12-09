//! Test helper: OsqueryContainer for testcontainers
//!
//! Provides Docker-based osquery instances for integration tests.

use std::borrow::Cow;
use testcontainers::core::WaitFor;
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
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // Integration tests can panic on infra failures
mod tests {
    use super::*;
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
}
