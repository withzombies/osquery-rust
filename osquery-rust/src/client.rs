use crate::_osquery as osquery;
use std::io::Error;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use thrift::protocol::{TBinaryInputProtocol, TBinaryOutputProtocol};

/// Trait for osquery daemon communication - enables mocking in tests.
///
/// This trait exposes only the methods that `Server` actually needs to communicate
/// with the osquery daemon. Implementing this trait allows creating mock clients
/// for testing without requiring a real osquery socket connection.
#[cfg_attr(test, mockall::automock)]
pub trait OsqueryClient: Send {
    /// Register this extension with the osquery daemon.
    fn register_extension(
        &mut self,
        info: osquery::InternalExtensionInfo,
        registry: osquery::ExtensionRegistry,
    ) -> thrift::Result<osquery::ExtensionStatus>;

    /// Deregister this extension from the osquery daemon.
    fn deregister_extension(
        &mut self,
        uuid: osquery::ExtensionRouteUUID,
    ) -> thrift::Result<osquery::ExtensionStatus>;

    /// Ping the osquery daemon to maintain the connection.
    fn ping(&mut self) -> thrift::Result<osquery::ExtensionStatus>;

    /// Execute a SQL query against osquery.
    fn query(&mut self, sql: String) -> thrift::Result<crate::ExtensionResponse>;

    /// Get column information for a SQL query without executing it.
    fn get_query_columns(&mut self, sql: String) -> thrift::Result<crate::ExtensionResponse>;
}

/// Production implementation of [`OsqueryClient`] using Thrift over Unix sockets.
pub struct ThriftClient {
    client: osquery::ExtensionManagerSyncClient<
        TBinaryInputProtocol<UnixStream>,
        TBinaryOutputProtocol<UnixStream>,
    >,
}

impl ThriftClient {
    pub fn new(socket_path: &str, _timeout: Duration) -> Result<Self, Error> {
        // todo: error handling, socket could be unable to connect to
        // todo: use timeout
        let socket_tx = UnixStream::connect(socket_path)?;
        let socket_rx = socket_tx.try_clone()?;

        let in_proto = TBinaryInputProtocol::new(socket_tx, true);
        let out_proto = TBinaryOutputProtocol::new(socket_rx, true);

        Ok(ThriftClient {
            client: osquery::ExtensionManagerSyncClient::new(in_proto, out_proto),
        })
    }
}

//
// Extension implements _osquery's Thrift API: trait TExtensionManagerSyncClient
//
impl osquery::TExtensionManagerSyncClient for ThriftClient {
    fn extensions(&mut self) -> thrift::Result<osquery::InternalExtensionList> {
        self.client.extensions()
    }

    fn options(&mut self) -> thrift::Result<osquery::InternalOptionList> {
        self.client.options()
    }

    fn register_extension(
        &mut self,
        info: osquery::InternalExtensionInfo,
        registry: osquery::ExtensionRegistry,
    ) -> thrift::Result<osquery::ExtensionStatus> {
        self.client.register_extension(info, registry)
    }

    fn deregister_extension(
        &mut self,
        _uuid: osquery::ExtensionRouteUUID,
    ) -> thrift::Result<osquery::ExtensionStatus> {
        self.client.deregister_extension(_uuid)
    }

    fn query(&mut self, _sql: String) -> thrift::Result<osquery::ExtensionResponse> {
        self.client.query(_sql)
    }

    fn get_query_columns(&mut self, _sql: String) -> thrift::Result<osquery::ExtensionResponse> {
        self.client.get_query_columns(_sql)
    }
}

//
// Extension implements _osquery's Thrift API: super-trait TExtensionSyncClient
//
impl osquery::TExtensionSyncClient for ThriftClient {
    fn ping(&mut self) -> thrift::Result<osquery::ExtensionStatus> {
        self.client.ping()
    }

    fn call(
        &mut self,
        _registry: String,
        _item: String,
        _request: osquery::ExtensionPluginRequest,
    ) -> thrift::Result<osquery::ExtensionResponse> {
        todo!()
    }

    fn shutdown(&mut self) -> thrift::Result<()> {
        self.client.shutdown()
    }
}

//
// ThriftClient implements our custom OsqueryClient trait
//
impl OsqueryClient for ThriftClient {
    fn register_extension(
        &mut self,
        info: osquery::InternalExtensionInfo,
        registry: osquery::ExtensionRegistry,
    ) -> thrift::Result<osquery::ExtensionStatus> {
        osquery::TExtensionManagerSyncClient::register_extension(&mut self.client, info, registry)
    }

    fn deregister_extension(
        &mut self,
        uuid: osquery::ExtensionRouteUUID,
    ) -> thrift::Result<osquery::ExtensionStatus> {
        osquery::TExtensionManagerSyncClient::deregister_extension(&mut self.client, uuid)
    }

    fn ping(&mut self) -> thrift::Result<osquery::ExtensionStatus> {
        osquery::TExtensionSyncClient::ping(&mut self.client)
    }

    fn query(&mut self, sql: String) -> thrift::Result<crate::ExtensionResponse> {
        osquery::TExtensionManagerSyncClient::query(&mut self.client, sql)
    }

    fn get_query_columns(&mut self, sql: String) -> thrift::Result<crate::ExtensionResponse> {
        osquery::TExtensionManagerSyncClient::get_query_columns(&mut self.client, sql)
    }
}

/// Type alias for backwards compatibility.
///
/// Existing code using `Client` will continue to work unchanged.
pub type Client = ThriftClient;
