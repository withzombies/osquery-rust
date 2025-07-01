use crate::_osquery::{
    ExtensionPluginRequest, ExtensionPluginResponse, ExtensionResponse, ExtensionStatus,
};
use crate::plugin::{OsqueryPlugin, Registry};
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
    fn gen_pack(&self, name: &str, value: &str) -> Result<String, String> {
        Err(format!("Pack '{}' not found", name))
    }
    
    /// Called when the plugin is shutting down
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
        ExtensionStatus::default()
    }

    fn generate(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        // Config plugins handle two actions: genConfig and genPack
        let action = req.get("action").map(|s| s.as_str()).unwrap_or("");
        
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
                        ExtensionResponseEnum::Success().with_response(response).into()
                    }
                    Err(e) => ExtensionResponseEnum::Failure(e).into(),
                }
            }
            "genPack" => {
                let name = req.get("name").cloned().unwrap_or_default();
                let value = req.get("value").cloned().unwrap_or_default();
                
                match self.plugin.gen_pack(&name, &value) {
                    Ok(pack_content) => {
                        let mut response = ExtensionPluginResponse::new();
                        let mut row = BTreeMap::new();
                        row.insert("pack".to_string(), pack_content);
                        response.push(row);
                        ExtensionResponseEnum::Success().with_response(response).into()
                    }
                    Err(e) => ExtensionResponseEnum::Failure(e).into(),
                }
            }
            _ => ExtensionResponseEnum::Failure(
                format!("Unknown config plugin action: {}", action)
            ).into(),
        }
    }

    fn update(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
        ExtensionResponseEnum::Failure("Config plugins do not support update".to_string()).into()
    }

    fn delete(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
        ExtensionResponseEnum::Failure("Config plugins do not support delete".to_string()).into()
    }

    fn insert(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
        ExtensionResponseEnum::Failure("Config plugins do not support insert".to_string()).into()
    }

    fn shutdown(&self) {
        self.plugin.shutdown();
    }
}