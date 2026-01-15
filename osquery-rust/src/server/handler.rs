/// Extension handler for processing osquery requests
use crate::_osquery as osquery;
use crate::plugin::{OsqueryPlugin, Registry};
use crate::util::OptionToThriftResult;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use strum::VariantNames;

pub struct Handler<P: OsqueryPlugin + Clone> {
    registry: HashMap<String, HashMap<String, P>>,
    shutdown_flag: Arc<AtomicBool>,
}

impl<P: OsqueryPlugin + Clone> Handler<P> {
    pub fn new(plugins: &[P], shutdown_flag: Arc<AtomicBool>) -> thrift::Result<Self> {
        let mut reg: HashMap<String, HashMap<String, P>> = HashMap::new();
        for var in Registry::VARIANTS {
            reg.insert((*var).to_string(), HashMap::new());
        }

        for plugin in plugins.iter() {
            reg.get_mut(plugin.registry().to_string().as_str())
                .ok_or_thrift_err(|| format!("Failed to register plugin {}", plugin.name()))?
                .insert(plugin.name(), plugin.clone());
        }

        Ok(Handler {
            registry: reg,
            shutdown_flag,
        })
    }
}

impl<P: OsqueryPlugin + Clone> osquery::ExtensionSyncHandler for Handler<P> {
    fn handle_ping(&self) -> thrift::Result<osquery::ExtensionStatus> {
        Ok(osquery::ExtensionStatus::default())
    }

    fn handle_call(
        &self,
        registry: String,
        item: String,
        request: osquery::ExtensionPluginRequest,
    ) -> thrift::Result<osquery::ExtensionResponse> {
        log::trace!("Registry: {registry}");
        log::trace!("Item: {item}");
        log::trace!("Request: {request:?}");

        let plugin = self
            .registry
            .get(registry.as_str())
            .ok_or_thrift_err(|| {
                format!(
                    "Failed to get registry:{} from registries",
                    registry.as_str()
                )
            })?
            .get(item.as_str())
            .ok_or_thrift_err(|| {
                format!(
                    "Failed to item:{} from registry:{}",
                    item.as_str(),
                    registry.as_str()
                )
            })?;

        Ok(plugin.handle_call(request))
    }

    fn handle_shutdown(&self) -> thrift::Result<()> {
        log::debug!("Shutdown RPC received from osquery");
        self.shutdown_flag.store(true, Ordering::Release);
        Ok(())
    }
}

impl<P: OsqueryPlugin + Clone> osquery::ExtensionManagerSyncHandler for Handler<P> {
    fn handle_extensions(&self) -> thrift::Result<osquery::InternalExtensionList> {
        // Extension management not supported - return empty list
        Ok(osquery::InternalExtensionList::new())
    }

    fn handle_options(&self) -> thrift::Result<osquery::InternalOptionList> {
        // Extension options not supported - return empty list
        Ok(osquery::InternalOptionList::new())
    }

    fn handle_register_extension(
        &self,
        _info: osquery::InternalExtensionInfo,
        _registry: osquery::ExtensionRegistry,
    ) -> thrift::Result<osquery::ExtensionStatus> {
        // Nested extension registration not supported
        Ok(osquery::ExtensionStatus {
            code: Some(1),
            message: Some("Extension registration not supported".to_string()),
            uuid: None,
        })
    }

    fn handle_deregister_extension(
        &self,
        _uuid: osquery::ExtensionRouteUUID,
    ) -> thrift::Result<osquery::ExtensionStatus> {
        // Nested extension deregistration not supported
        Ok(osquery::ExtensionStatus {
            code: Some(1),
            message: Some("Extension deregistration not supported".to_string()),
            uuid: None,
        })
    }

    fn handle_query(&self, _sql: String) -> thrift::Result<osquery::ExtensionResponse> {
        // Query execution not supported
        Ok(osquery::ExtensionResponse::new(
            osquery::ExtensionStatus {
                code: Some(1),
                message: Some("Query execution not supported".to_string()),
                uuid: None,
            },
            vec![],
        ))
    }

    fn handle_get_query_columns(&self, _sql: String) -> thrift::Result<osquery::ExtensionResponse> {
        // Query column introspection not supported
        Ok(osquery::ExtensionResponse::new(
            osquery::ExtensionStatus {
                code: Some(1),
                message: Some("Query column introspection not supported".to_string()),
                uuid: None,
            },
            vec![],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::{Plugin, TablePlugin};

    struct TestTable;

    impl crate::plugin::ReadOnlyTable for TestTable {
        fn name(&self) -> String {
            "test_handler_table".to_string()
        }

        fn columns(&self) -> Vec<crate::plugin::ColumnDef> {
            vec![crate::plugin::ColumnDef::new(
                "test_column",
                crate::plugin::ColumnType::Text,
                crate::plugin::ColumnOptions::empty(),
            )]
        }

        fn generate(&self, _request: crate::ExtensionPluginRequest) -> crate::ExtensionResponse {
            crate::ExtensionResponse::new(crate::_osquery::ExtensionStatus::default(), vec![])
        }

        fn shutdown(&self) {}
    }

    #[test]
    fn test_handler_new_empty_plugins() {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins: Vec<Plugin> = vec![];

        let handler = Handler::new(&plugins, shutdown_flag).unwrap();

        // Should have empty registries for each registry type
        assert!(handler.registry.contains_key("table"));
        assert!(handler.registry.contains_key("config"));
        assert!(handler.registry.contains_key("logger"));
    }

    #[test]
    fn test_handler_new_with_plugin() {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins = vec![Plugin::Table(TablePlugin::from_readonly_table(TestTable))];

        let handler = Handler::new(&plugins, shutdown_flag).unwrap();

        // Should have the plugin in the table registry
        let table_registry = handler.registry.get("table").unwrap();
        assert!(table_registry.contains_key("test_handler_table"));
    }

    #[test]
    fn test_handle_ping_returns_default_status() {
        use osquery::ExtensionSyncHandler;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins: Vec<Plugin> = vec![];
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();

        let status = handler.handle_ping().unwrap();

        // Default status has code None (success in osquery terms)
        assert_eq!(status.code, None);
    }

    #[test]
    fn test_handle_call_routes_to_plugin() {
        use osquery::ExtensionSyncHandler;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins = vec![Plugin::Table(TablePlugin::from_readonly_table(TestTable))];
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();

        // Table plugins require an "action" key in the request
        let mut request = osquery::ExtensionPluginRequest::new();
        request.insert("action".to_string(), "generate".to_string());

        let response = handler
            .handle_call(
                "table".to_string(),
                "test_handler_table".to_string(),
                request,
            )
            .unwrap();

        // Should get a successful response (code None means success in osquery terms)
        let status = response.status.unwrap();
        assert_eq!(status.code, None);
    }

    #[test]
    fn test_handle_call_unknown_registry_returns_error() {
        use osquery::ExtensionSyncHandler;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins: Vec<Plugin> = vec![];
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();

        let request = osquery::ExtensionPluginRequest::new();
        let result = handler.handle_call(
            "nonexistent_registry".to_string(),
            "some_item".to_string(),
            request,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_handle_call_unknown_item_returns_error() {
        use osquery::ExtensionSyncHandler;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins: Vec<Plugin> = vec![];
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();

        let request = osquery::ExtensionPluginRequest::new();
        let result = handler.handle_call(
            "table".to_string(),
            "nonexistent_table".to_string(),
            request,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_handle_shutdown_sets_flag() {
        use osquery::ExtensionSyncHandler;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins: Vec<Plugin> = vec![];
        let handler = Handler::new(&plugins, Arc::clone(&shutdown_flag)).unwrap();

        assert!(!shutdown_flag.load(Ordering::Acquire));

        handler.handle_shutdown().unwrap();

        assert!(shutdown_flag.load(Ordering::Acquire));
    }

    #[test]
    fn test_handle_extensions_returns_empty_list() {
        use osquery::ExtensionManagerSyncHandler;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins: Vec<Plugin> = vec![];
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();

        let extensions = handler.handle_extensions().unwrap();

        assert!(extensions.is_empty());
    }

    #[test]
    fn test_handle_options_returns_empty_list() {
        use osquery::ExtensionManagerSyncHandler;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins: Vec<Plugin> = vec![];
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();

        let options = handler.handle_options().unwrap();

        assert!(options.is_empty());
    }

    #[test]
    fn test_handle_register_extension_returns_not_supported() {
        use osquery::ExtensionManagerSyncHandler;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins: Vec<Plugin> = vec![];
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();

        let info = osquery::InternalExtensionInfo::default();
        let registry = osquery::ExtensionRegistry::new();
        let status = handler.handle_register_extension(info, registry).unwrap();

        assert_eq!(status.code, Some(1));
        assert!(status.message.unwrap().contains("not supported"));
    }

    #[test]
    fn test_handle_deregister_extension_returns_not_supported() {
        use osquery::ExtensionManagerSyncHandler;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins: Vec<Plugin> = vec![];
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();

        let status = handler.handle_deregister_extension(12345).unwrap();

        assert_eq!(status.code, Some(1));
        assert!(status.message.unwrap().contains("not supported"));
    }

    #[test]
    fn test_handle_query_returns_not_supported() {
        use osquery::ExtensionManagerSyncHandler;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins: Vec<Plugin> = vec![];
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();

        let response = handler.handle_query("SELECT 1".to_string()).unwrap();

        let status = response.status.unwrap();
        assert_eq!(status.code, Some(1));
        assert!(status.message.unwrap().contains("not supported"));
    }

    #[test]
    fn test_handle_get_query_columns_returns_not_supported() {
        use osquery::ExtensionManagerSyncHandler;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let plugins: Vec<Plugin> = vec![];
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();

        let response = handler
            .handle_get_query_columns("SELECT 1".to_string())
            .unwrap();

        let status = response.status.unwrap();
        assert_eq!(status.code, Some(1));
        assert!(status.message.unwrap().contains("not supported"));
    }
}
