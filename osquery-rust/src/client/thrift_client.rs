/// Thrift client implementation for osquery communication
use crate::_osquery as osquery;
use crate::client::trait_def::OsqueryClient;
use std::io::Error;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use thrift::protocol::{TBinaryInputProtocol, TBinaryOutputProtocol};

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::time::Duration;


    #[test]
    fn test_thrift_client_new_with_invalid_path() {
        let result = ThriftClient::new("/nonexistent/socket", Duration::from_secs(1));
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().kind(), ErrorKind::NotFound);
    }

    #[test]
    fn test_thrift_client_new_with_empty_path() {
        let result = ThriftClient::new("", Duration::from_secs(1));
        assert!(result.is_err());
    }

    #[test]
    fn test_thrift_client_new_with_directory_path() {
        let result = ThriftClient::new("/tmp", Duration::from_secs(1));
        assert!(result.is_err());
    }


    #[test]
    fn test_client_type_alias() {
        use std::mem;
        
        assert_eq!(mem::size_of::<Client>(), mem::size_of::<ThriftClient>());
        assert_eq!(std::any::type_name::<Client>(), std::any::type_name::<ThriftClient>());
    }
}