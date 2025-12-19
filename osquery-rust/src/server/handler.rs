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
        // Extension deregistration not supported
        Ok(osquery::ExtensionStatus {
            code: Some(1),
            message: Some("Extension deregistration not supported".to_string()),
            uuid: None,
        })
    }

    fn handle_query(&self, _sql: String) -> thrift::Result<osquery::ExtensionResponse> {
        // Query execution not implemented for extensions
        let status = osquery::ExtensionStatus {
            code: Some(1),
            message: Some("Query execution not implemented for extensions".to_string()),
            uuid: None,
        };
        Ok(osquery::ExtensionResponse {
            status: Some(status),
            response: Some(vec![]),
        })
    }

    fn handle_get_query_columns(&self, _sql: String) -> thrift::Result<osquery::ExtensionResponse> {
        // Query column information not implemented for extensions
        let status = osquery::ExtensionStatus {
            code: Some(1),
            message: Some("Query column information not implemented for extensions".to_string()),
            uuid: None,
        };
        Ok(osquery::ExtensionResponse {
            status: Some(status),
            response: Some(vec![]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::_osquery::osquery::{ExtensionSyncHandler, ExtensionManagerSyncHandler};
    use crate::plugin::TablePlugin;

    struct TestTable;

    impl crate::plugin::ReadOnlyTable for TestTable {
        fn name(&self) -> String {
            "test_table".to_string()
        }

        fn columns(&self) -> Vec<crate::plugin::ColumnDef> {
            vec![crate::plugin::ColumnDef::new(
                "test_column", 
                crate::plugin::ColumnType::Text,
                crate::plugin::ColumnOptions::empty()
            )]
        }

        fn generate(&self, _request: crate::ExtensionPluginRequest) -> crate::ExtensionResponse {
            crate::ExtensionResponse::new(osquery::ExtensionStatus::default(), vec![])
        }

        fn shutdown(&self) {}
    }

    #[test]
    fn test_handler_new() {
        use crate::plugin::Plugin;
        
        let plugins = vec![
            Plugin::Table(TablePlugin::from_readonly_table(TestTable))
        ];
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        
        let handler_result = Handler::new(&plugins, shutdown_flag);
        assert!(handler_result.is_ok());
    }

    #[test]
    fn test_handler_ping() {
        let plugins: Vec<crate::plugin::Plugin> = vec![];
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();
        let result = handler.handle_ping();
        assert!(result.is_ok());
        
        let status = result.unwrap();
        assert_eq!(status.code, Some(0));
        assert_eq!(status.message, Some("OK".to_string()));
    }

    #[test]
    fn test_handler_shutdown() {
        let plugins: Vec<crate::plugin::Plugin> = vec![];
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        
        let handler = Handler::new(&plugins, shutdown_flag.clone()).unwrap();
        assert!(!shutdown_flag.load(Ordering::Acquire));
        
        let result = handler.handle_shutdown();
        assert!(result.is_ok());
        
        assert!(shutdown_flag.load(Ordering::Acquire));
    }

    #[test]
    fn test_handler_extensions() {
        let plugins: Vec<crate::plugin::Plugin> = vec![];
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();
        let result = handler.handle_extensions();
        assert!(result.is_ok());
        
        let extensions = result.unwrap();
        assert!(extensions.is_empty());
    }

    #[test]
    fn test_handler_options() {
        let plugins: Vec<crate::plugin::Plugin> = vec![];
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();
        let result = handler.handle_options();
        assert!(result.is_ok());
        
        let options = result.unwrap();
        assert!(options.is_empty());
    }

    #[test]
    fn test_handler_query_not_implemented() {
        let plugins: Vec<crate::plugin::Plugin> = vec![];
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();
        let result = handler.handle_query("SELECT 1".to_string());
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert_eq!(response.status.as_ref().unwrap().code, Some(1));
        assert!(response.status.as_ref().unwrap().message.as_ref().unwrap().contains("not implemented"));
    }

    #[test]
    fn test_handler_get_query_columns_not_implemented() {
        let plugins: Vec<crate::plugin::Plugin> = vec![];
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        
        let handler = Handler::new(&plugins, shutdown_flag).unwrap();
        let result = handler.handle_get_query_columns("SELECT 1".to_string());
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert_eq!(response.status.as_ref().unwrap().code, Some(1));
        assert!(response.status.as_ref().unwrap().message.as_ref().unwrap().contains("not implemented"));
    }
}