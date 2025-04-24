use crate::_osquery::ExtensionStatus;
use crate::plugin::Registry;
use crate::{ExtensionPluginResponse, _osquery as osquery};
use std::collections::BTreeMap;

pub trait OsqueryPlugin {
    // Name is the name used to refer to the plugin (eg. the name of the
    // table the plugin implements).
    fn name(&self) -> String;

    // RegistryName is which "registry" the plugin should be added to.
    // Valid names are ["config", "logger", "table"].
    fn registry(&self) -> Registry;

    // Routes returns the detailed information about the interface exposed
    // by the plugin. See the example plugins for samples.
    fn routes(&self) -> osquery::ExtensionPluginResponse;

    // Ping implements a health check for the plugin. If the plugin is in a
    // healthy state, StatusOK should be returned.
    fn ping(&self) -> osquery::ExtensionStatus;

    // Call requests the plugin to perform its defined behavior, returning
    // a response containing the result.
    // Request: {"action": "generate", "context": "{\"constraints\":[{\"name\":\"h1\",\"list\":[],\"affinity\":\"TEXT\"},{\"name\":\"h2\",\"list\":[],\"affinity\":\"INTEGER\"},{\"name\":\"h3\",\"list\":[],\"affinity\":\"TEXT\"}],\"colsUsed\":[\"h3\",\"h2\",\"h1\"],\"colsUsedBitset\":7}"}
    fn generate(&self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse;

    fn update(&self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        let mut resp = BTreeMap::<String, String>::new();
        resp.insert("status".to_string(), "readonly".to_string());
        osquery::ExtensionResponse::new(ExtensionStatus::new(1, None, None), vec![resp])
    }
    fn delete(&self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        let mut resp = BTreeMap::<String, String>::new();
        resp.insert("status".to_string(), "readonly".to_string());
        osquery::ExtensionResponse::new(ExtensionStatus::new(1, None, None), vec![resp])
    }
    fn insert(&self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        let mut resp = BTreeMap::<String, String>::new();
        resp.insert("status".to_string(), "readonly".to_string());
        osquery::ExtensionResponse::new(ExtensionStatus::new(1, None, None), vec![resp])
    }

    // Shutdown alerts the plugin to stop.
    fn shutdown(&self);
}
