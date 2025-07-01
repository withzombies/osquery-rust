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
        let mut config_map = HashMap::new();

        // Static configuration that enables file events on /tmp
        let config = r#"{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10,
    "enable_file_events": "true",
    "disable_events": "false",
    "events_expiry": "3600",
    "events_max": "50000"
  },
  "schedule": {
    "file_events": {
      "query": "SELECT * FROM file_events;",
      "interval": 10,
      "removed": false
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
