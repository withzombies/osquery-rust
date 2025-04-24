use crate::_osquery as osquery;
use std::io::Error;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use thrift::protocol::{TBinaryInputProtocol, TBinaryOutputProtocol};

pub struct Client {
    client: osquery::ExtensionManagerSyncClient<
        TBinaryInputProtocol<UnixStream>,
        TBinaryOutputProtocol<UnixStream>,
    >,
}

impl Client {
    pub fn new(socket_path: &str, _timeout: Duration) -> Result<Self, Error> {
        // todo: error handling, socket could be unable to connect to
        // todo: use timeout
        let socket_tx = UnixStream::connect(socket_path)?;
        let socket_rx = socket_tx.try_clone()?;

        let in_proto = TBinaryInputProtocol::new(socket_tx, true);
        let out_proto = TBinaryOutputProtocol::new(socket_rx, true);

        Ok(Client {
            client: osquery::ExtensionManagerSyncClient::new(in_proto, out_proto),
        })
    }
}

//
// Extension implements _osquery's Thrift API: trait TExtensionManagerSyncClient
//
impl osquery::TExtensionManagerSyncClient for Client {
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
impl osquery::TExtensionSyncClient for Client {
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
