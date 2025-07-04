use clap::crate_name;
use std::collections::HashMap;
use std::io::Error;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;
use strum::VariantNames;
use thrift::protocol::*;
use thrift::transport::*;

use crate::_osquery as osquery;
use crate::_osquery::{TExtensionManagerSyncClient, TExtensionSyncClient};
use crate::client::Client;
use crate::plugin::{OsqueryPlugin, Plugin, Registry};
use crate::util::OptionToThriftResult;

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);
const DEFAULT_PING_INTERVAL: Duration = Duration::from_millis(5000);

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
    //mutex: Mutex<u32>,
    uuid: Option<osquery::ExtensionRouteUUID>,
    // Used to ensure tests wait until the server is actually started
    started: bool,
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

    pub fn run(&mut self) -> thrift::Result<()> {
        self.start()?;
        loop {
            self.client.ping()?;
            thread::sleep(self.ping_interval);
        }
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

        let processor = osquery::ExtensionManagerSyncProcessor::new(Handler::new(&self.plugins)?);
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

        match server.listen_uds(listen_path.clone()) {
            Ok(_) => {}
            Err(e) => {
                log::error!("FATAL: {e} while binding to {listen_path}")
            }
        }
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
}

struct Handler<P: OsqueryPlugin + Clone> {
    registry: HashMap<String, HashMap<String, P>>,
}

impl<P: OsqueryPlugin + Clone> Handler<P> {
    fn new(plugins: &[P]) -> thrift::Result<Self> {
        let mut reg: HashMap<String, HashMap<String, P>> = HashMap::new();
        for var in Registry::VARIANTS {
            reg.insert((*var).to_string(), HashMap::new());
        }

        for plugin in plugins.iter() {
            reg.get_mut(plugin.registry().to_string().as_str())
                .ok_or_thrift_err(|| format!("Failed to register plugin {}", plugin.name()))?
                .insert(plugin.name(), plugin.clone());
        }

        Ok(Handler { registry: reg })
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
        log::trace!("Shutdown");

        self.registry.iter().for_each(|(_, v)| {
            v.iter().for_each(|(_, p)| {
                p.shutdown();
            });
        });

        Ok(())
    }
}

impl<P: OsqueryPlugin + Clone> osquery::ExtensionManagerSyncHandler for Handler<P> {
    fn handle_extensions(&self) -> thrift::Result<osquery::InternalExtensionList> {
        todo!()
    }

    fn handle_options(&self) -> thrift::Result<osquery::InternalOptionList> {
        todo!()
    }

    fn handle_register_extension(
        &self,
        _info: osquery::InternalExtensionInfo,
        _registry: osquery::ExtensionRegistry,
    ) -> thrift::Result<osquery::ExtensionStatus> {
        todo!()
    }

    fn handle_deregister_extension(
        &self,
        _uuid: osquery::ExtensionRouteUUID,
    ) -> thrift::Result<osquery::ExtensionStatus> {
        todo!()
    }

    fn handle_query(&self, _sql: String) -> thrift::Result<osquery::ExtensionResponse> {
        todo!()
    }

    fn handle_get_query_columns(&self, _sql: String) -> thrift::Result<osquery::ExtensionResponse> {
        todo!()
    }
}
