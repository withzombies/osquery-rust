pub(crate) mod column_def;
pub use column_def::ColumnDef;
pub use column_def::ColumnType;

pub(crate) mod query_constraint;
#[allow(unused_imports)]
pub use query_constraint::QueryConstraints;

use crate::_osquery as osquery;
use crate::_osquery::{
    ExtensionPluginRequest, ExtensionPluginResponse, ExtensionResponse, ExtensionStatus,
};
use crate::plugin::{OsqueryPlugin, Registry};
use std::collections::BTreeMap;

pub trait Table: OsqueryPlugin + 'static {
    fn plugin_name(&self) -> String;
    fn columns(&self) -> Vec<ColumnDef>;
    fn select(&self, _req: crate::ExtensionPluginRequest) -> crate::ExtensionResponse;
}

impl<R: Table> OsqueryPlugin for R {
    fn name(&self) -> String {
        self.plugin_name()
    }

    fn registry(&self) -> Registry {
        todo!()
    }

    fn routes(&self) -> osquery::ExtensionPluginResponse {
        let mut resp = ExtensionPluginResponse::new();

        for column in &self.columns() {
            let mut r: BTreeMap<String, String> = BTreeMap::new();

            r.insert("id".to_string(), "column".to_string());
            r.insert("name".to_string(), column.name());
            r.insert("type".to_string(), column.t());
            r.insert("op".to_string(), "0".to_string());

            resp.push(r);
        }

        resp
    }

    fn ping(&self) -> ExtensionStatus {
        todo!()
    }

    fn generate(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        self.select(req)
    }

    fn shutdown(&self) {
        log::trace!("Shutting down plugin: {}", self.name());
    }
}
