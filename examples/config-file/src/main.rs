mod cli;

use clap::Parser;
use cli::Args;
use log::info;
use osquery_rust_ng::plugin::{ConfigPlugin, Plugin};
use osquery_rust_ng::prelude::*;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    #[test]
    fn test_name() {
        let plugin = FileConfigPlugin::new("/tmp/config.json".into(), "/tmp/packs".into());
        assert_eq!(plugin.name(), "file_config");
    }

    #[test]
    fn test_gen_config_reads_valid_json_file() {
        // Create a temp config file with valid JSON
        let mut config_file = NamedTempFile::new().expect("create temp file");
        writeln!(
            config_file,
            r#"{{"options": {{"host_identifier": "test"}}}}"#
        )
        .expect("write config");

        let plugin = FileConfigPlugin::new(
            config_file.path().to_string_lossy().into_owned(),
            "/tmp/packs".into(),
        );

        let result = plugin.gen_config();
        assert!(result.is_ok(), "gen_config should succeed: {:?}", result);

        let config_map = result.expect("should have config");
        assert!(config_map.contains_key("main"));

        // Verify content
        let main_config = config_map.get("main").expect("should have main");
        assert!(main_config.contains("host_identifier"));
    }

    #[test]
    fn test_gen_config_fails_on_missing_file() {
        let plugin =
            FileConfigPlugin::new("/nonexistent/path/config.json".into(), "/tmp/packs".into());

        let result = plugin.gen_config();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read"));
    }

    #[test]
    fn test_gen_config_fails_on_invalid_json() {
        // Create a temp config file with invalid JSON
        let mut config_file = NamedTempFile::new().expect("create temp file");
        writeln!(config_file, "not valid json {{{{").expect("write config");

        let plugin = FileConfigPlugin::new(
            config_file.path().to_string_lossy().into_owned(),
            "/tmp/packs".into(),
        );

        let result = plugin.gen_config();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid JSON"));
    }

    #[test]
    fn test_gen_pack_reads_valid_pack_file() {
        // Create a temp packs directory with a pack file
        let packs_dir = TempDir::new().expect("create temp dir");
        let pack_path = packs_dir.path().join("test_pack.json");
        fs::write(
            &pack_path,
            r#"{"queries": {"test": {"query": "SELECT 1;"}}}"#,
        )
        .expect("write pack");

        let plugin = FileConfigPlugin::new(
            "/tmp/config.json".into(),
            packs_dir.path().to_string_lossy().into_owned(),
        );

        let result = plugin.gen_pack("test_pack", "");
        assert!(result.is_ok(), "gen_pack should succeed: {:?}", result);

        let content = result.expect("should have content");
        assert!(content.contains("queries"));
    }

    #[test]
    fn test_gen_pack_fails_on_missing_pack() {
        let plugin = FileConfigPlugin::new("/tmp/config.json".into(), "/tmp/packs".into());

        let result = plugin.gen_pack("nonexistent", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read pack"));
    }

    #[test]
    fn test_gen_pack_rejects_path_traversal_dotdot() {
        let plugin = FileConfigPlugin::new("/tmp/config.json".into(), "/tmp/packs".into());

        let result = plugin.gen_pack("../../../etc/passwd", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid pack name"));
    }

    #[test]
    fn test_gen_pack_rejects_path_traversal_slash() {
        let plugin = FileConfigPlugin::new("/tmp/config.json".into(), "/tmp/packs".into());

        let result = plugin.gen_pack("/etc/passwd", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid pack name"));
    }

    #[test]
    fn test_gen_pack_rejects_path_traversal_backslash() {
        let plugin = FileConfigPlugin::new("/tmp/config.json".into(), "/tmp/packs".into());

        let result = plugin.gen_pack("..\\..\\etc\\passwd", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid pack name"));
    }

    #[test]
    fn test_gen_pack_fails_on_invalid_json() {
        // Create a temp packs directory with invalid JSON
        let packs_dir = TempDir::new().expect("create temp dir");
        let pack_path = packs_dir.path().join("bad_pack.json");
        fs::write(&pack_path, "not valid json").expect("write pack");

        let plugin = FileConfigPlugin::new(
            "/tmp/config.json".into(),
            packs_dir.path().to_string_lossy().into_owned(),
        );

        let result = plugin.gen_pack("bad_pack", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid JSON"));
    }
}
