mod cli;

use clap::Parser;
use cli::Args;
use log::info;
use osquery_rust::plugin::{ConfigPlugin, Plugin};
use osquery_rust::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

struct FileConfigPlugin {
    config_path: String,
    packs_dir: String,
}

impl FileConfigPlugin {
    fn new(config_path: String, packs_dir: String) -> Self {
        Self {
            config_path,
            packs_dir,
        }
    }
}

impl ConfigPlugin for FileConfigPlugin {
    fn name(&self) -> String {
        "file_config".to_string()
    }

    fn gen_config(&self) -> Result<HashMap<String, String>, String> {
        let mut config_map = HashMap::new();

        // Read the main configuration file
        match fs::read_to_string(&self.config_path) {
            Ok(content) => {
                // Validate that it's valid JSON
                if let Err(e) = serde_json::from_str::<serde_json::Value>(&content) {
                    return Err(format!("Invalid JSON in config file: {e}"));
                }
                config_map.insert("main".to_string(), content);
            }
            Err(e) => {
                return Err(format!(
                    "Failed to read config file '{}': {e}",
                    self.config_path
                ));
            }
        }

        Ok(config_map)
    }

    fn gen_pack(&self, name: &str, _value: &str) -> Result<String, String> {
        // Sanitize the pack name to prevent path traversal
        if name.contains("..") || name.contains('/') || name.contains('\\') {
            return Err(format!("Invalid pack name: {name}"));
        }

        let pack_file = format!("{name}.json");
        let pack_path = Path::new(&self.packs_dir).join(pack_file);

        match fs::read_to_string(&pack_path) {
            Ok(content) => {
                // Validate that it's valid JSON
                if let Err(e) = serde_json::from_str::<serde_json::Value>(&content) {
                    return Err(format!("Invalid JSON in pack file: {e}"));
                }
                Ok(content)
            }
            Err(e) => Err(format!("Failed to read pack '{name}': {e}")),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    if args.verbose {
        info!("Starting config plugin...");
        info!("Config file: {}", args.config_file);
        info!("Packs directory: {}", args.packs_dir);
        info!("Socket: {}", args.socket);
    }

    // Create the config plugin
    let config_plugin = FileConfigPlugin::new(args.config_file, args.packs_dir);

    // Create and run the server
    let mut server = Server::new(Some("file_config"), &args.socket)?;
    server.register_plugin(Plugin::config(config_plugin));

    if args.verbose {
        info!("Config plugin started");
    }

    server.run()?;

    Ok(())
}
