pub(crate) mod column_def;
pub use column_def::ColumnDef;
pub use column_def::ColumnType;

pub(crate) mod query_constraint;
#[allow(unused_imports)]
pub use query_constraint::QueryConstraints;

use crate::_osquery::{
    ExtensionPluginRequest, ExtensionPluginResponse, ExtensionResponse, ExtensionStatus,
};
use crate::plugin::ExtensionResponseEnum::SuccessWithId;
use crate::plugin::_enums::response::ExtensionResponseEnum;
use crate::plugin::{OsqueryPlugin, Registry};
use enum_dispatch::enum_dispatch;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
#[enum_dispatch(OsqueryPlugin)]
pub enum TablePlugin {
    Writeable(Arc<Mutex<dyn Table>>),
    Readonly(Arc<dyn ReadOnlyTable>),
}

impl TablePlugin {
    pub fn from_writeable_table<R: Table>(table: R) -> Self {
        TablePlugin::Writeable(Arc::new(Mutex::new(table)))
    }

    pub fn from_readonly_table<R: ReadOnlyTable>(table: R) -> Self {
        TablePlugin::Readonly(Arc::new(table))
    }
}

impl OsqueryPlugin for TablePlugin {
    fn name(&self) -> String {
        match self {
            TablePlugin::Writeable(table) => {
                let Ok(table) = table.lock() else {
                    return "unable-to-get-table-name".to_string();
                };

                table.name()
            }
            TablePlugin::Readonly(table) => table.name(),
        }
    }

    fn registry(&self) -> Registry {
        Registry::Table
    }

    fn routes(&self) -> ExtensionPluginResponse {
        let mut resp = ExtensionPluginResponse::new();

        let columns = match self {
            TablePlugin::Writeable(table) => {
                let Ok(table) = table.lock() else {
                    log::error!("Plugin was unavailable, could not lock table");
                    return resp;
                };

                table.columns()
            }
            TablePlugin::Readonly(table) => table.columns(),
        };

        for column in &columns {
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
        ExtensionStatus::default()
    }

    fn generate(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        match self {
            TablePlugin::Writeable(table) => {
                let Ok(table) = table.lock() else {
                    return ExtensionResponseEnum::Failure(
                        "Plugin was unavailable, could not lock table".to_string(),
                    )
                    .into();
                };

                table.generate(req)
            }
            TablePlugin::Readonly(table) => table.generate(req),
        }
    }

    fn update(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        let TablePlugin::Writeable(table) = self else {
            return ExtensionResponseEnum::Readonly().into();
        };

        let Ok(mut table) = table.lock() else {
            return ExtensionResponseEnum::Failure(
                "Plugin was unavailable, could not lock table".to_string(),
            )
            .into();
        };

        let Some(id) = req.get("id") else {
            return ExtensionResponseEnum::Failure("Could not deserialize the id".to_string())
                .into();
        };

        let Ok(id) = id.parse::<u64>() else {
            return ExtensionResponseEnum::Failure("Could not parse the id".to_string()).into();
        };

        let Some(json_value_array) = req.get("json_value_array") else {
            return ExtensionResponseEnum::Failure(
                "Could not deserialize the json_value_array".to_string(),
            )
            .into();
        };

        // "json_value_array": "[1,\"lol\"]"
        let Ok(row) = serde_json::from_str::<Value>(json_value_array) else {
            return ExtensionResponseEnum::Failure(
                "Could not parse the json_value_array".to_string(),
            )
            .into();
        };

        match table.update(id, &row) {
            UpdateResult::Success => ExtensionResponseEnum::Success().into(),
            UpdateResult::Constraint => ExtensionResponseEnum::Constraint().into(),
            UpdateResult::Err(err) => ExtensionResponseEnum::Failure(err).into(),
        }
    }

    fn delete(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        let TablePlugin::Writeable(table) = self else {
            return ExtensionResponseEnum::Readonly().into();
        };

        let Ok(mut table) = table.lock() else {
            return ExtensionResponseEnum::Failure(
                "Plugin was unavailable, could not lock table".to_string(),
            )
            .into();
        };

        let Some(id) = req.get("id") else {
            return ExtensionResponseEnum::Failure("Could not deserialize the id".to_string())
                .into();
        };

        let Ok(id) = id.parse::<u64>() else {
            return ExtensionResponseEnum::Failure("Could not parse the id".to_string()).into();
        };

        match table.delete(id) {
            DeleteResult::Success => ExtensionResponseEnum::Success().into(),
            DeleteResult::Err(e) => {
                ExtensionResponseEnum::Failure(format!("Plugin error {}", e).to_string()).into()
            }
        }
    }

    fn insert(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        let TablePlugin::Writeable(table) = self else {
            return ExtensionResponseEnum::Readonly().into();
        };

        let Ok(mut table) = table.lock() else {
            return ExtensionResponseEnum::Failure(
                "Plugin was unavailable, could not lock table".to_string(),
            )
            .into();
        };

        let auto_rowid = req.get("auto_rowid").unwrap_or(&"false".to_string()) == "true";

        let Some(json_value_array) = req.get("json_value_array") else {
            return ExtensionResponseEnum::Failure(
                "Could not deserialize the json_value_array".to_string(),
            )
            .into();
        };

        // "json_value_array": "[1,\"lol\"]"
        let Ok(row) = serde_json::from_str::<Value>(json_value_array) else {
            return ExtensionResponseEnum::Failure(
                "Could not parse the json_value_array".to_string(),
            )
            .into();
        };

        match table.insert(auto_rowid, &row) {
            InsertResult::Success(rowid) => SuccessWithId(rowid).into(),
            InsertResult::Constraint => ExtensionResponseEnum::Constraint().into(),
            InsertResult::Err(err) => ExtensionResponseEnum::Failure(err).into(),
        }
    }

    fn shutdown(&self) {
        log::trace!("Shutting down plugin: {}", self.name());

        match self {
            TablePlugin::Writeable(table) => {
                let Ok(table) = table.lock() else {
                    log::error!("Plugin was unavailable, could not lock table");
                    return;
                };

                table.shutdown();
            }
            TablePlugin::Readonly(table) => table.shutdown(),
        }
    }
}

pub enum InsertResult {
    Success(u64),
    Constraint,
    Err(String),
}

pub enum UpdateResult {
    Success,
    Constraint,
    Err(String),
}

pub enum DeleteResult {
    Success,
    Err(String),
}

pub trait Table: Send + Sync + 'static {
    fn name(&self) -> String;
    fn columns(&self) -> Vec<ColumnDef>;
    fn generate(&self, req: crate::ExtensionPluginRequest) -> crate::ExtensionResponse;
    fn update(&mut self, rowid: u64, row: &serde_json::Value) -> UpdateResult;
    fn delete(&mut self, rowid: u64) -> DeleteResult;
    fn insert(&mut self, auto_rowid: bool, row: &serde_json::value::Value) -> InsertResult;
    fn shutdown(&self);
}

pub trait ReadOnlyTable: Send + Sync + 'static {
    fn name(&self) -> String;
    fn columns(&self) -> Vec<ColumnDef>;
    fn generate(&self, req: crate::ExtensionPluginRequest) -> crate::ExtensionResponse;
    fn shutdown(&self);
}
