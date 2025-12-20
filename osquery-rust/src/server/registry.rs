/// Plugin registry management for osquery extensions
use crate::_osquery as osquery;
use crate::plugin::OsqueryPlugin;
use std::collections::BTreeMap;

/// Manages plugin registry generation for osquery
pub struct RegistryManager;

impl RegistryManager {
    /// Generate registry for osquery registration
    pub fn generate_registry<P>(plugins: &[P]) -> thrift::Result<osquery::ExtensionRegistry>
    where
        P: OsqueryPlugin + Clone + Send + Sync + 'static,
    {
        let mut registry = BTreeMap::new();

        // Group plugins by registry type (table, config, logger)
        for plugin in plugins {
            let registry_name = plugin.registry().to_string();
            let plugin_name = plugin.name();
            let routes = plugin.routes();

            // Get or create the route table for this registry type
            let route_table = registry.entry(registry_name).or_insert_with(BTreeMap::new);

            // Add this plugin's routes to the registry
            route_table.insert(plugin_name, routes);
        }

        Ok(registry)
    }

    /// Create extension info for registration
    pub fn extension_info(name: &str) -> osquery::InternalExtensionInfo {
        osquery::InternalExtensionInfo {
            name: Some(name.to_string()),
            version: Some("2.0.0".to_string()),
            sdk_version: Some("5.0.0".to_string()),
            min_sdk_version: Some("5.0.0".to_string()),
        }
    }
}
