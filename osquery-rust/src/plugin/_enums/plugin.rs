use crate::_osquery as osquery;
use crate::_osquery::{ExtensionPluginRequest, ExtensionResponse};
use crate::plugin::config::{ConfigPlugin, ConfigPluginWrapper};
use crate::plugin::logger::{LoggerPlugin, LoggerPluginWrapper};
use crate::plugin::table::{ReadOnlyTable, TablePlugin};
use crate::plugin::Registry;
use crate::plugin::{OsqueryPlugin, Table};
use std::sync::Arc;

#[derive(Clone)]
pub enum Plugin {
    Config(Arc<dyn OsqueryPlugin>),
    Logger(Arc<dyn OsqueryPlugin>),
    Table(TablePlugin),
}

impl Plugin {
    pub fn table<T: Table + 'static>(t: T) -> Self {
        Plugin::Table(TablePlugin::from_writeable_table(t))
    }

    pub fn readonly_table<T: ReadOnlyTable + 'static>(t: T) -> Self {
        Plugin::Table(TablePlugin::from_readonly_table(t))
    }

    pub fn config<C: ConfigPlugin + 'static>(c: C) -> Self {
        Plugin::Config(Arc::new(ConfigPluginWrapper::new(c)))
    }

    pub fn logger<L: LoggerPlugin + 'static>(l: L) -> Self {
        Plugin::Logger(Arc::new(LoggerPluginWrapper::new(l)))
    }
}

impl OsqueryPlugin for Plugin {
    // Name is the name used to refer to the plugin (e.g. the name of the
    // table the plugin implements).
    fn name(&self) -> String {
        match self {
            Plugin::Config(c) => c.name(),
            Plugin::Logger(l) => l.name(),
            Plugin::Table(t) => t.name(),
        }
    }

    // Registry is which "registry" the plugin should be added to.
    fn registry(&self) -> Registry {
        match self {
            Plugin::Config(_) => Registry::Config,
            Plugin::Logger(_) => Registry::Logger,
            Plugin::Table(_) => Registry::Table,
        }
    }

    // Routes returns detailed information about the interface exposed
    // by the plugin. See the example plugins for implementation details.
    //pub(crate) fn routes(&self) -> osquery::ExtensionPluginResponse {
    fn routes(&self) -> osquery::ExtensionPluginResponse {
        match self {
            Plugin::Config(c) => c.routes(),
            Plugin::Logger(l) => l.routes(),
            Plugin::Table(t) => t.routes(),
        }
    }

    // Ping implements the plugin's health check. If the plugin is in a
    // healthy state, Status OK should be returned.
    fn ping(&self) -> osquery::ExtensionStatus {
        match self {
            Plugin::Config(c) => c.ping(),
            Plugin::Logger(l) => l.ping(),
            Plugin::Table(t) => t.ping(),
        }
    }

    // Call requests the plugin to perform its defined behavior, returning
    // a response containing the result.
    fn handle_call(&self, request: ExtensionPluginRequest) -> ExtensionResponse {
        match self {
            Plugin::Config(c) => c.handle_call(request),
            Plugin::Logger(l) => l.handle_call(request),
            Plugin::Table(t) => t.handle_call(request),
        }
    }

    // Shutdown notifies the plugin to stop.
    fn shutdown(&self) {
        match self {
            Plugin::Config(c) => c.shutdown(),
            Plugin::Logger(l) => l.shutdown(),
            Plugin::Table(t) => t.shutdown(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::logger::LogStatus;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // Test ConfigPlugin implementation with observable shutdown
    struct TestConfigPlugin {
        shutdown_called: Arc<AtomicBool>,
    }

    impl TestConfigPlugin {
        fn new() -> (Self, Arc<AtomicBool>) {
            let flag = Arc::new(AtomicBool::new(false));
            (
                Self {
                    shutdown_called: Arc::clone(&flag),
                },
                flag,
            )
        }
    }

    impl ConfigPlugin for TestConfigPlugin {
        fn name(&self) -> String {
            "test_config".to_string()
        }

        fn gen_config(&self) -> Result<HashMap<String, String>, String> {
            let mut config = HashMap::new();
            config.insert("main".to_string(), r#"{"options":{}}"#.to_string());
            Ok(config)
        }

        fn gen_pack(&self, name: &str, _value: &str) -> Result<String, String> {
            if name == "test_pack" {
                Ok(r#"{"queries":{}}"#.to_string())
            } else {
                Err(format!("Pack '{name}' not found"))
            }
        }

        fn shutdown(&self) {
            self.shutdown_called.store(true, Ordering::SeqCst);
        }
    }

    // Test LoggerPlugin implementation with observable shutdown
    struct TestLoggerPlugin {
        shutdown_called: Arc<AtomicBool>,
    }

    impl TestLoggerPlugin {
        fn new() -> (Self, Arc<AtomicBool>) {
            let flag = Arc::new(AtomicBool::new(false));
            (
                Self {
                    shutdown_called: Arc::clone(&flag),
                },
                flag,
            )
        }
    }

    impl LoggerPlugin for TestLoggerPlugin {
        fn name(&self) -> String {
            "test_logger".to_string()
        }

        fn log_string(&self, _message: &str) -> Result<(), String> {
            Ok(())
        }

        fn log_status(&self, _statuses: &LogStatus) -> Result<(), String> {
            Ok(())
        }

        fn shutdown(&self) {
            self.shutdown_called.store(true, Ordering::SeqCst);
        }
    }

    // ===== Config Plugin Dispatch Tests =====

    #[test]
    fn test_plugin_config_factory() {
        let (config, _flag) = TestConfigPlugin::new();
        let plugin = Plugin::config(config);
        assert!(matches!(plugin, Plugin::Config(_)));
    }

    #[test]
    fn test_plugin_config_name() {
        let (config, _flag) = TestConfigPlugin::new();
        let plugin = Plugin::config(config);
        assert_eq!(plugin.name(), "test_config");
    }

    #[test]
    fn test_plugin_config_registry() {
        let (config, _flag) = TestConfigPlugin::new();
        let plugin = Plugin::config(config);
        assert_eq!(plugin.registry(), Registry::Config);
    }

    #[test]
    fn test_plugin_config_routes() {
        let (config, _flag) = TestConfigPlugin::new();
        let plugin = Plugin::config(config);
        let routes = plugin.routes();
        // Config plugins return empty routes
        assert!(routes.is_empty());
    }

    #[test]
    fn test_plugin_config_ping() {
        let (config, _flag) = TestConfigPlugin::new();
        let plugin = Plugin::config(config);
        let status = plugin.ping();
        assert_eq!(status.code, Some(0));
    }

    #[test]
    fn test_plugin_config_handle_call() {
        let (config, _flag) = TestConfigPlugin::new();
        let plugin = Plugin::config(config);
        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "genConfig".to_string());

        let response = plugin.handle_call(request);
        let status = response.status.as_ref();
        assert_eq!(status.and_then(|s| s.code), Some(0));
    }

    #[test]
    fn test_plugin_config_shutdown() {
        let (config, shutdown_flag) = TestConfigPlugin::new();
        let plugin = Plugin::config(config);

        // Verify shutdown hasn't been called yet
        assert!(!shutdown_flag.load(Ordering::SeqCst));

        // Call shutdown via Plugin dispatch
        plugin.shutdown();

        // Verify shutdown was actually called on the inner plugin
        assert!(shutdown_flag.load(Ordering::SeqCst));
    }

    // ===== Logger Plugin Dispatch Tests =====

    #[test]
    fn test_plugin_logger_factory() {
        let (logger, _flag) = TestLoggerPlugin::new();
        let plugin = Plugin::logger(logger);
        assert!(matches!(plugin, Plugin::Logger(_)));
    }

    #[test]
    fn test_plugin_logger_name() {
        let (logger, _flag) = TestLoggerPlugin::new();
        let plugin = Plugin::logger(logger);
        assert_eq!(plugin.name(), "test_logger");
    }

    #[test]
    fn test_plugin_logger_registry() {
        let (logger, _flag) = TestLoggerPlugin::new();
        let plugin = Plugin::logger(logger);
        assert_eq!(plugin.registry(), Registry::Logger);
    }

    #[test]
    fn test_plugin_logger_routes() {
        let (logger, _flag) = TestLoggerPlugin::new();
        let plugin = Plugin::logger(logger);
        let routes = plugin.routes();
        // Logger plugins return routes with their log type
        // The exact content depends on LoggerPluginWrapper implementation
        assert!(routes.len() <= 1);
    }

    #[test]
    fn test_plugin_logger_ping() {
        let (logger, _flag) = TestLoggerPlugin::new();
        let plugin = Plugin::logger(logger);
        let status = plugin.ping();
        assert_eq!(status.code, Some(0));
    }

    #[test]
    fn test_plugin_logger_handle_call() {
        let (logger, _flag) = TestLoggerPlugin::new();
        let plugin = Plugin::logger(logger);
        let mut request: BTreeMap<String, String> = BTreeMap::new();
        request.insert("action".to_string(), "init".to_string());

        let response = plugin.handle_call(request);
        let status = response.status.as_ref();
        assert_eq!(status.and_then(|s| s.code), Some(0));
    }

    #[test]
    fn test_plugin_logger_shutdown() {
        let (logger, shutdown_flag) = TestLoggerPlugin::new();
        let plugin = Plugin::logger(logger);

        // Verify shutdown hasn't been called yet
        assert!(!shutdown_flag.load(Ordering::SeqCst));

        // Call shutdown via Plugin dispatch
        plugin.shutdown();

        // Verify shutdown was actually called on the inner plugin
        assert!(shutdown_flag.load(Ordering::SeqCst));
    }
}
