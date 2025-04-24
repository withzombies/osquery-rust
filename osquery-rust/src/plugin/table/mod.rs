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
use std::sync::{Arc, Mutex};

pub fn create_readonly_response() -> ExtensionResponse {
    let mut resp = BTreeMap::<String, String>::new();
    resp.insert("status".to_string(), "readonly".to_string());
    osquery::ExtensionResponse::new(
        ExtensionStatus::new(1, Some("Table is read-only".to_string()), None),
        vec![resp],
    )
}

#[derive(Clone)]
pub struct TablePluginWrapper {
    inner: Arc<Mutex<dyn Table>>,
}

impl TablePluginWrapper {
    pub fn new(inner: Arc<Mutex<dyn Table>>) -> Self {
        Self { inner }
    }
}

impl OsqueryPlugin for TablePluginWrapper {
    fn name(&self) -> String {
        self.inner.lock().unwrap().name()
    }

    fn registry(&self) -> Registry {
        todo!()
    }

    fn routes(&self) -> osquery::ExtensionPluginResponse {
        let mut resp = ExtensionPluginResponse::new();

        for column in &self.inner.lock().unwrap().columns() {
            let mut r: BTreeMap<String, String> = BTreeMap::new();

            r.insert("id".to_string(), "column".to_string());
            r.insert("name".to_string(), column.name());
            r.insert("type".to_string(), column.t());
            r.insert("op".to_string(), column.o());

            resp.push(r);
        }

        resp
    }

    fn ping(&self) -> ExtensionStatus {
        todo!()
    }

    fn generate(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        self.inner.lock().unwrap().select(req)
    }

    fn update(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        self.inner.lock().unwrap().update(req)
    }

    fn delete(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        let Some(id) = req.get("id") else {
            return create_readonly_response();
        };

        let Ok(id) = id.parse::<u64>() else {
            return create_readonly_response();
        };

        match self.inner.lock().unwrap().delete(id) {
            Ok(_) => {
                let mut resp = BTreeMap::<String, String>::new();
                resp.insert("status".to_string(), "success".to_string());
                ExtensionResponse::new(ExtensionStatus::new(0, "OK".to_string(), None), vec![resp])
            }
            Err(_) => create_readonly_response(),
        }
    }

    fn insert(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        self.inner.lock().unwrap().insert(req)
    }

    fn shutdown(&self) {
        log::trace!("Shutting down plugin: {}", self.name());
    }
}

pub trait Table: Send + Sync + 'static {
    fn name(&self) -> String;
    fn columns(&self) -> Vec<ColumnDef>;
    fn select(&self, req: crate::ExtensionPluginRequest) -> crate::ExtensionResponse;
    fn update(&mut self, req: ExtensionPluginRequest) -> ExtensionResponse;
    fn delete(&mut self, id: u64) -> Result<(), std::io::Error>;
    fn insert(&mut self, req: ExtensionPluginRequest) -> ExtensionResponse;
}
