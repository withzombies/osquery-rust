mod cli;

use clap::Parser;
use cli::Args;
use log::info;
use osquery_rust_ng::plugin::{ConfigPlugin, Plugin};
use osquery_rust_ng::prelude::*;
use std::collections::HashMap;

struct FileEventsConfigPlugin;

impl ConfigPlugin for FileEventsConfigPlugin {
    fn name(&self) -> String {
        "static_config".to_string()
    }

    fn gen_config(&self) -> Result<HashMap<String, String>, String> {
        // Write marker file if configured (for testing)
        // Silently ignore write errors - test will detect missing marker
        if let Ok(marker_path) = std::env::var("TEST_CONFIG_MARKER_FILE") {
            let _ = std::fs::write(&marker_path, "Config generated");
        }

        let mut config_map = HashMap::new();

        // Static configuration that enables file events on /tmp
        // Also includes a fast scheduled query for testing log_snapshot functionality
        let config = r#"{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 0,
    "enable_file_events": "true",
    "disable_events": "false",
    "events_expiry": "3600",
    "events_max": "50000"
  },
  "schedule": {
    "file_events": {
      "query": "SELECT * FROM file_events;",
      "interval": 10,
      "removed": false,
      "snapshot": true
    },
    "osquery_info_snapshot": {
      "query": "SELECT version, build_platform FROM osquery_info;",
      "interval": 3,
      "snapshot": true
    }
  },
  "file_paths": {
    "/tmp": ["%%"]
  }
}"#;

        config_map.insert("main".to_string(), config.to_string());
        Ok(config_map)
    }

    fn gen_pack(&self, name: &str, _value: &str) -> Result<String, String> {
        Err(format!("Pack '{name}' not found"))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    if args.verbose {
        info!("Starting file events config plugin...");
        info!("Socket: {}", args.socket);
    }

    // Create and run the server
    let mut server = Server::new(Some("static_config"), &args.socket)?;
    server.register_plugin(Plugin::config(FileEventsConfigPlugin));

    if args.verbose {
        info!("File events config plugin started");
    }

    server.run()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        let plugin = FileEventsConfigPlugin;
        assert_eq!(plugin.name(), "static_config");
    }

    #[test]
    fn test_gen_config_returns_valid_json() {
        let plugin = FileEventsConfigPlugin;
        let result = plugin.gen_config();

        assert!(result.is_ok(), "gen_config should succeed");
        let config_map = result.expect("should have config");

        // Should have "main" key
        assert!(config_map.contains_key("main"));

        // Config should be valid JSON
        let main_config = config_map.get("main").expect("should have main");
        let parsed: serde_json::Value =
            serde_json::from_str(main_config).expect("should be valid JSON");

        // Verify expected structure
        assert!(parsed.get("options").is_some());
        assert!(parsed.get("schedule").is_some());
        assert!(parsed.get("file_paths").is_some());
    }

    #[test]
    fn test_gen_config_has_file_events_enabled() {
        let plugin = FileEventsConfigPlugin;
        let config_map = plugin.gen_config().expect("should succeed");
        let main_config = config_map.get("main").expect("should have main");
        let parsed: serde_json::Value =
            serde_json::from_str(main_config).expect("should be valid JSON");

        // Check file events are enabled
        let enable_file_events = parsed
            .get("options")
            .and_then(|o| o.get("enable_file_events"))
            .and_then(|v| v.as_str());
        assert_eq!(enable_file_events, Some("true"));
    }

    #[test]
    fn test_gen_pack_returns_error_for_unknown_pack() {
        let plugin = FileEventsConfigPlugin;
        let result = plugin.gen_pack("nonexistent", "");

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }
}
