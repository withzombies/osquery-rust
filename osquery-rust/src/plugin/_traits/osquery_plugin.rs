use crate::plugin::Registry;
pub trait OsqueryPlugin: Send + Sync {
    fn name(&self) -> String;
    fn registry(&self) -> Registry;
    fn routes(&self) -> crate::_osquery::ExtensionPluginResponse;
    fn ping(&self) -> crate::_osquery::ExtensionStatus;
    fn handle_call(
        &self,
        request: crate::_osquery::ExtensionPluginRequest,
    ) -> crate::_osquery::ExtensionResponse;
    fn shutdown(&self);
}
