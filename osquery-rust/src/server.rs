use clap::crate_name;
use std::collections::HashMap;
use std::io::Error;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use strum::VariantNames;
use thrift::protocol::*;
use thrift::transport::*;
use thrift::{ApplicationError, ApplicationErrorKind};

use crate::_osquery as osquery;
use crate::_osquery::{TExtensionManagerSyncClient, TExtensionSyncClient};
use crate::client::Client;
use crate::plugin::{OsqueryPlugin, Plugin, Registry};
use crate::util::OptionToThriftResult;

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);
const DEFAULT_PING_INTERVAL: Duration = Duration::from_millis(5000);

/// Handle that allows stopping the server from another thread.
///
/// This handle can be cloned and shared across threads. It provides a way for
/// external code to request a graceful shutdown of the server.
///
/// # Thread Safety
///
/// `ServerStopHandle` is `Clone + Send + Sync` and can be safely shared between
/// threads. Multiple calls to `stop()` are safe and idempotent.
///
/// # Example
///
/// ```ignore
/// let mut server = Server::new(None, "/path/to/socket")?;
/// let handle = server.get_stop_handle();
///
/// // In another thread:
/// std::thread::spawn(move || {
///     // ... some condition ...
///     handle.stop();
/// });
///
/// server.run()?; // Will exit when stop() is called
/// ```
#[derive(Clone)]
pub struct ServerStopHandle {
    shutdown_flag: Arc<AtomicBool>,
}

impl ServerStopHandle {
    /// Request the server to stop.
    ///
    /// This method is idempotent - multiple calls are safe.
    /// The server will exit its run loop on the next iteration.
    pub fn stop(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
    }

    /// Check if the server is still running.
    ///
    /// Returns `true` if the server has not been requested to stop,
    /// `false` if `stop()` has been called.
    pub fn is_running(&self) -> bool {
        !self.shutdown_flag.load(Ordering::Acquire)
    }
}

#[allow(clippy::type_complexity)]
pub struct Server<P: OsqueryPlugin + Clone + Send + Sync + 'static> {
    name: String,
    socket_path: String,
    client: Client,
    plugins: Vec<P>,
    server: Option<
        thrift::server::TServer<
            osquery::ExtensionManagerSyncProcessor<Handler<P>>,
            Box<dyn TReadTransportFactory>,
            Box<dyn TInputProtocolFactory>,
            Box<dyn TWriteTransportFactory>,
            Box<dyn TOutputProtocolFactory>,
        >,
    >,
    #[allow(dead_code)]
    transport: Option<
        osquery::ExtensionSyncClient<
            TBinaryInputProtocol<UnixStream>,
            TBinaryOutputProtocol<UnixStream>,
        >,
    >,
    #[allow(dead_code)]
    timeout: Duration,
    ping_interval: Duration,
    uuid: Option<osquery::ExtensionRouteUUID>,
    // Used to ensure tests wait until the server is actually started
    started: bool,
    shutdown_flag: Arc<AtomicBool>,
}

impl<P: OsqueryPlugin + Clone + Send + 'static> Server<P> {
    pub fn new(name: Option<&str>, socket_path: &str) -> Result<Self, Error> {
        let mut reg: HashMap<String, HashMap<String, Plugin>> = HashMap::new();
        for var in Registry::VARIANTS {
            reg.insert((*var).to_string(), HashMap::new());
        }

        let name = name.unwrap_or(crate_name!());

        let client = Client::new(socket_path, Default::default())?;

        Ok(Server {
            name: name.to_string(),
            socket_path: socket_path.to_string(),
            client,
            plugins: Vec::new(),
            server: None,
            transport: None,
            timeout: DEFAULT_TIMEOUT,
            ping_interval: DEFAULT_PING_INTERVAL,
            uuid: None,
            started: false,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    ///
    /// Registers a plugin, something which implements the OsqueryPlugin trait.
    /// Consumes the plugin.
    ///
    pub fn register_plugin(&mut self, plugin: P) -> &Self {
        self.plugins.push(plugin);
        self
    }

    /// Run the server, blocking until shutdown is requested.
    ///
    /// This method starts the server, registers with osquery, and enters a loop
    /// that pings osquery periodically. The loop exits when shutdown is triggered
    /// by any of:
    /// - osquery calling the shutdown RPC
    /// - Connection to osquery being lost
    /// - `stop()` being called from another thread
    ///
    /// For signal handling (SIGTERM/SIGINT), use `run_with_signal_handling()` instead.
    pub fn run(&mut self) -> thrift::Result<()> {
        self.start()?;
        self.run_loop();
        self.shutdown_and_cleanup();
        Ok(())
    }

    /// Run the server with signal handling enabled (Unix only).
    ///
    /// This method registers handlers for SIGTERM and SIGINT that will trigger
    /// graceful shutdown. Use this instead of `run()` if you want the server to
    /// respond to OS signals (e.g., systemd sending SIGTERM, or Ctrl+C sending SIGINT).
    ///
    /// The loop exits when shutdown is triggered by any of:
    /// - SIGTERM or SIGINT signal received
    /// - osquery calling the shutdown RPC
    /// - Connection to osquery being lost
    /// - `stop()` being called from another thread
    ///
    /// # Platform Support
    ///
    /// This method is only available on Unix platforms. For Windows, use `run()`
    /// and implement your own signal handling.
    #[cfg(unix)]
    pub fn run_with_signal_handling(&mut self) -> thrift::Result<()> {
        use signal_hook::consts::{SIGINT, SIGTERM};
        use signal_hook::flag;

        // Register signal handlers that set our shutdown flag.
        // signal_hook::flag::register atomically sets the bool when signal received.
        // Errors are rare (e.g., invalid signal number) and non-fatal - signals
        // just won't trigger shutdown, but other shutdown mechanisms still work.
        if let Err(e) = flag::register(SIGINT, self.shutdown_flag.clone()) {
            log::warn!("Failed to register SIGINT handler: {e}");
        }
        if let Err(e) = flag::register(SIGTERM, self.shutdown_flag.clone()) {
            log::warn!("Failed to register SIGTERM handler: {e}");
        }

        self.start()?;
        self.run_loop();
        self.shutdown_and_cleanup();
        Ok(())
    }

    /// The main ping loop. Exits when should_shutdown() returns true.
    fn run_loop(&mut self) {
        while !self.should_shutdown() {
            if let Err(e) = self.client.ping() {
                log::warn!("Ping failed, initiating shutdown: {e}");
                self.request_shutdown();
                break;
            }
            thread::sleep(self.ping_interval);
        }
    }

    /// Common shutdown logic: deregister, notify plugins, cleanup socket.
    fn shutdown_and_cleanup(&mut self) {
        log::info!("Shutting down");

        // Deregister from osquery (best-effort, allows faster cleanup than timeout)
        if let Some(uuid) = self.uuid {
            if let Err(e) = self.client.deregister_extension(uuid) {
                log::warn!("Failed to deregister from osquery: {e}");
            }
        }

        self.notify_plugins_shutdown();
        self.cleanup_socket();
    }

    fn start(&mut self) -> thrift::Result<()> {
        let stat = self.client.register_extension(
            osquery::InternalExtensionInfo {
                name: Some(self.name.clone()),
                version: Some("1.0".to_string()),
                sdk_version: Some("Unknown".to_string()),
                min_sdk_version: Some("Unknown".to_string()),
            },
            self.generate_registry()?,
        )?;

        //if stat.code != Some(0) {
        log::info!(
            "Status {} registering extension {} ({}): {}",
            stat.code.unwrap_or(0),
            self.name,
            stat.uuid.unwrap_or(0),
            stat.message.unwrap_or_else(|| "No message".to_string())
        );
        //}

        self.uuid = stat.uuid;
        let listen_path = format!("{}.{}", self.socket_path, self.uuid.unwrap_or(0));

        let processor = osquery::ExtensionManagerSyncProcessor::new(Handler::new(
            &self.plugins,
            self.shutdown_flag.clone(),
        )?);
        let i_tr_fact: Box<dyn TReadTransportFactory> =
            Box::new(TBufferedReadTransportFactory::new());
        let i_pr_fact: Box<dyn TInputProtocolFactory> =
            Box::new(TBinaryInputProtocolFactory::new());
        let o_tr_fact: Box<dyn TWriteTransportFactory> =
            Box::new(TBufferedWriteTransportFactory::new());
        let o_pr_fact: Box<dyn TOutputProtocolFactory> =
            Box::new(TBinaryOutputProtocolFactory::new());

        let mut server =
            thrift::server::TServer::new(i_tr_fact, i_pr_fact, o_tr_fact, o_pr_fact, processor, 10);

        server.listen_uds(listen_path.clone()).map_err(|e| {
            thrift::Error::Application(ApplicationError::new(
                ApplicationErrorKind::InternalError,
                format!("Failed to bind to {listen_path}: {e}"),
            ))
        })?;
        self.server = Some(server);

        self.started = true;

        Ok(())
    }

    fn generate_registry(&self) -> thrift::Result<osquery::ExtensionRegistry> {
        let mut registry = osquery::ExtensionRegistry::new();

        for var in Registry::VARIANTS {
            registry.insert((*var).to_string(), osquery::ExtensionRouteTable::new());
        }

        for plugin in self.plugins.iter() {
            registry
                .get_mut(plugin.registry().to_string().as_str())
                .ok_or_thrift_err(|| format!("Failed to register plugin {}", plugin.name()))?
                .insert(plugin.name(), plugin.routes());
        }
        Ok(registry)
    }

    /// Check if shutdown has been requested.
    fn should_shutdown(&self) -> bool {
        self.shutdown_flag.load(Ordering::Acquire)
    }

    /// Request shutdown by setting the shutdown flag.
    fn request_shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
    }

    /// Notify all registered plugins that shutdown is occurring.
    /// Uses catch_unwind to ensure all plugins are notified even if one panics.
    fn notify_plugins_shutdown(&self) {
        log::debug!("Notifying {} plugins of shutdown", self.plugins.len());
        for plugin in &self.plugins {
            let plugin_name = plugin.name();
            if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                plugin.shutdown();
            })) {
                log::error!("Plugin '{plugin_name}' panicked during shutdown: {e:?}");
            }
        }
    }

    /// Clean up the socket file created during start().
    /// Logs errors (except NotFound, which is expected if socket was already cleaned up).
    fn cleanup_socket(&self) {
        let Some(uuid) = self.uuid else {
            log::debug!("No socket to clean up (uuid not set)");
            return;
        };

        let socket_path = format!("{}.{}", self.socket_path, uuid);
        log::debug!("Cleaning up socket: {socket_path}");

        if let Err(e) = std::fs::remove_file(&socket_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!("Failed to remove socket file {socket_path}: {e}");
            }
        }
    }

    /// Get a handle that can be used to stop the server from another thread.
    ///
    /// The returned handle can be cloned and shared across threads. Calling
    /// `stop()` on the handle will cause the server's `run()` method to exit
    /// gracefully on the next iteration.
    pub fn get_stop_handle(&self) -> ServerStopHandle {
        ServerStopHandle {
            shutdown_flag: self.shutdown_flag.clone(),
        }
    }

    /// Request the server to stop.
    ///
    /// This is a convenience method equivalent to calling `stop()` on a
    /// `ServerStopHandle`. The server will exit its `run()` loop on the next
    /// iteration.
    pub fn stop(&self) {
        self.request_shutdown();
    }

    /// Check if the server is still running.
    ///
    /// Returns `true` if the server has not been requested to stop,
    /// `false` if `stop()` has been called or shutdown has been triggered
    /// by another mechanism (e.g., osquery shutdown RPC, connection loss).
    pub fn is_running(&self) -> bool {
        !self.should_shutdown()
    }
}

struct Handler<P: OsqueryPlugin + Clone> {
    registry: HashMap<String, HashMap<String, P>>,
    shutdown_flag: Arc<AtomicBool>,
}

impl<P: OsqueryPlugin + Clone> Handler<P> {
    fn new(plugins: &[P], shutdown_flag: Arc<AtomicBool>) -> thrift::Result<Self> {
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
