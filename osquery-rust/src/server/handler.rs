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
