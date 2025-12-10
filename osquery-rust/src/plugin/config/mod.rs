use crate::_osquery::{ExtensionPluginResponse, ExtensionResponse, ExtensionStatus};
use crate::plugin::{ExtensionResponseEnum, OsqueryPlugin, Registry};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Trait for implementing configuration plugins in osquery-rust.
///
/// Configuration plugins provide osquery with its configuration data,
/// which can come from various sources like files, HTTP endpoints, or
/// other custom sources.
pub trait ConfigPlugin: Send + Sync + 'static {
    /// The name of the configuration plugin
    fn name(&self) -> String;

    /// Generate configuration data.
    ///
    /// Returns a map of config source names to JSON-encoded configuration strings.
    /// The map typically contains a "main" key with the primary configuration.
    fn gen_config(&self) -> Result<HashMap<String, String>, String>;

    /// Generate pack configuration.
    ///
    /// Called when pack content is not provided inline with the configuration.
    /// The `name` parameter is the pack name, and `value` is any additional context.
    fn gen_pack(&self, name: &str, _value: &str) -> Result<String, String> {
        Err(format!("Pack '{name}' not found"))
    }

    /// Called when the plugin is shutting down.
    fn shutdown(&self) {}
}

/// Wrapper that adapts ConfigPlugin to OsqueryPlugin
#[derive(Clone)]
pub struct ConfigPluginWrapper {
    plugin: Arc<dyn ConfigPlugin>,
}

impl ConfigPluginWrapper {
    pub fn new<C: ConfigPlugin>(plugin: C) -> Self {
        Self {
            plugin: Arc::new(plugin),
        }
    }
}

impl OsqueryPlugin for ConfigPluginWrapper {
    fn name(&self) -> String {
        self.plugin.name()
    }

    fn registry(&self) -> Registry {
        Registry::Config
    }

    fn routes(&self) -> ExtensionPluginResponse {
        // Config plugins don't expose routes like table plugins do
        ExtensionPluginResponse::new()
    }

    fn ping(&self) -> ExtensionStatus {
        ExtensionStatus::new(0, None, None)
    }

    fn handle_call(&self, request: crate::_osquery::ExtensionPluginRequest) -> ExtensionResponse {
        // Config plugins handle two actions: genConfig and genPack
        let action = request.get("action").map(|s| s.as_str()).unwrap_or("");

        match action {
            "genConfig" => {
                match self.plugin.gen_config() {
                    Ok(config_map) => {
                        let mut response = ExtensionPluginResponse::new();
                        let mut row = BTreeMap::new();

                        // Convert the config map to the expected format
                        for (key, value) in config_map {
                            row.insert(key, value);
                        }

                        response.push(row);
                        let status = ExtensionStatus::new(0, None, None);
                        ExtensionResponse::new(status, response)
                    }
                    Err(e) => ExtensionResponseEnum::Failure(e).into(),
                }
            }
            "genPack" => {
                let name = request.get("name").cloned().unwrap_or_default();
                let value = request.get("value").cloned().unwrap_or_default();

                match self.plugin.gen_pack(&name, &value) {
                    Ok(pack_content) => {
                        let mut response = ExtensionPluginResponse::new();
                        let mut row = BTreeMap::new();
                        row.insert("pack".to_string(), pack_content);
                        response.push(row);
                        let status = ExtensionStatus::new(0, None, None);
                        ExtensionResponse::new(status, response)
                    }
                    Err(e) => ExtensionResponseEnum::Failure(e).into(),
                }
            }
            _ => ExtensionResponseEnum::Failure(format!("Unknown config plugin action: {action}"))
                .into(),
        }
    }

    fn shutdown(&self) {
        self.plugin.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::OsqueryPlugin;

    /// Helper to get first row from ExtensionResponse safely
    fn get_first_row(resp: &ExtensionResponse) -> Option<&BTreeMap<String, String>> {
        resp.response.as_ref().and_then(|r| r.first())
    }

    struct TestConfig {
        config: HashMap<String, String>,
        packs: HashMap<String, String>,
        fail_config: bool,
    }

    impl TestConfig {
        fn new() -> Self {
            let mut config = HashMap::new();
            config.insert("main".to_string(), r#"{"options":{}}"#.to_string());
            Self {
                config,
                packs: HashMap::new(),
                fail_config: false,
            }
        }

        fn with_pack(mut self, name: &str, content: &str) -> Self {
            self.packs.insert(name.to_string(), content.to_string());
            self
        }

        fn failing() -> Self {
            Self {
                config: HashMap::new(),
                packs: HashMap::new(),
                fail_config: true,
            }
        }

        fn empty() -> Self {
            Self {
                config: HashMap::new(),
                packs: HashMap::new(),
                fail_config: false,
            }
        }
    }

    impl ConfigPlugin for TestConfig {
        fn name(&self) -> String {
            "test_config".to_string()
        }

        fn gen_config(&self) -> Result<HashMap<String, String>, String> {
            if self.fail_config {
                Err("Config generation failed".to_string())
            } else {
                Ok(self.config.clone())
            }
        }

        fn gen_pack(&self, name: &str, _value: &str) -> Result<String, String> {
            self.packs
                .get(name)
                .cloned()
                .ok_or_else(|| format!("Pack '{name}' not found"))
        }
    }

    #[test]
    fn test_gen_config_returns_config_map() {
        let config = TestConfig::new();
        let wrapper = ConfigPluginWrapper::new(config);

        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "genConfig".to_string());

        let response = wrapper.handle_call(request);

        // Verify success status
        let status = response.status.as_ref();
        assert!(status.is_some());
        assert_eq!(status.and_then(|s| s.code), Some(0));

        // Verify response contains config data
        let row = get_first_row(&response);
        assert!(row.is_some());
        assert!(row.map(|r| r.contains_key("main")).unwrap_or(false));
    }

    #[test]
    fn test_gen_config_failure_returns_error() {
        let config = TestConfig::failing();
        let wrapper = ConfigPluginWrapper::new(config);

        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "genConfig".to_string());

        let response = wrapper.handle_call(request);

        // Verify failure status code 1
        let status = response.status.as_ref();
        assert!(status.is_some());
        assert_eq!(status.and_then(|s| s.code), Some(1));

        // Verify response contains failure status
        let row = get_first_row(&response);
        assert!(row.is_some());
        assert_eq!(
            row.and_then(|r| r.get("status")).map(|s| s.as_str()),
            Some("failure")
        );
    }

    #[test]
    fn test_gen_config_empty_map_returns_empty_response() {
        let config = TestConfig::empty();
        let wrapper = ConfigPluginWrapper::new(config);

        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "genConfig".to_string());

        let response = wrapper.handle_call(request);

        // Verify success status
        let status = response.status.as_ref();
        assert_eq!(status.and_then(|s| s.code), Some(0));

        // Response should have one row but it's empty
        let empty_vec = vec![];
        let rows = response.response.as_ref().unwrap_or(&empty_vec);
        assert_eq!(rows.len(), 1);
        let row = get_first_row(&response);
        assert!(row.is_some());
        assert!(row.map(|r| r.is_empty()).unwrap_or(false));
    }

    #[test]
    fn test_gen_pack_returns_pack_content() {
        let config = TestConfig::new().with_pack("security", r#"{"queries":{}}"#);
        let wrapper = ConfigPluginWrapper::new(config);

        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "genPack".to_string());
        request.insert("name".to_string(), "security".to_string());

        let response = wrapper.handle_call(request);

        let status = response.status.as_ref();
        assert_eq!(status.and_then(|s| s.code), Some(0));

        let row = get_first_row(&response);
        assert!(row.is_some());
        assert!(row.map(|r| r.contains_key("pack")).unwrap_or(false));
        assert_eq!(
            row.and_then(|r| r.get("pack")).map(|s| s.as_str()),
            Some(r#"{"queries":{}}"#)
        );
    }

    #[test]
    fn test_gen_pack_not_found_returns_error() {
        let config = TestConfig::new(); // No packs
        let wrapper = ConfigPluginWrapper::new(config);

        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "genPack".to_string());
        request.insert("name".to_string(), "nonexistent".to_string());

        let response = wrapper.handle_call(request);

        let status = response.status.as_ref();
        assert_eq!(status.and_then(|s| s.code), Some(1));

        let row = get_first_row(&response);
        assert!(row.is_some());
        assert_eq!(
            row.and_then(|r| r.get("status")).map(|s| s.as_str()),
            Some("failure")
        );
    }

    #[test]
    fn test_unknown_action_returns_error() {
        let config = TestConfig::new();
        let wrapper = ConfigPluginWrapper::new(config);

        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "invalidAction".to_string());

        let response = wrapper.handle_call(request);

        let status = response.status.as_ref();
        assert_eq!(status.and_then(|s| s.code), Some(1));
    }

    #[test]
    fn test_config_plugin_registry() {
        let config = TestConfig::new();
        let wrapper = ConfigPluginWrapper::new(config);
        assert_eq!(wrapper.registry(), Registry::Config);
    }

    #[test]
    fn test_config_plugin_routes_empty() {
        let config = TestConfig::new();
        let wrapper = ConfigPluginWrapper::new(config);
        assert!(wrapper.routes().is_empty());
    }

    #[test]
    fn test_config_plugin_name() {
        let config = TestConfig::new();
        let wrapper = ConfigPluginWrapper::new(config);
        assert_eq!(wrapper.name(), "test_config");
    }

    #[test]
    fn test_config_plugin_ping() {
        let config = TestConfig::new();
        let wrapper = ConfigPluginWrapper::new(config);
        let status = wrapper.ping();
        assert_eq!(status.code, Some(0));
    }
}
