pub(crate) mod column_def;
pub use column_def::ColumnDef;
pub use column_def::ColumnType;

pub(crate) mod query_constraint;
#[allow(unused_imports)]
pub use query_constraint::QueryConstraints;

use crate::_osquery::{
    osquery, ExtensionPluginRequest, ExtensionPluginResponse, ExtensionResponse, ExtensionStatus,
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

    fn handle_call(&self, request: crate::_osquery::ExtensionPluginRequest) -> ExtensionResponse {
        let action = request.get("action").map(|s| s.as_str()).unwrap_or("");

        log::trace!("Action: {action}");

        match action {
            "columns" => {
                let resp = self.routes();
                ExtensionResponse::new(
                    osquery::ExtensionStatus {
                        code: Some(0),
                        message: Some("Success".to_string()),
                        uuid: Default::default(),
                    },
                    resp,
                )
            }
            "generate" => self.generate(request),
            "update" => self.update(request),
            "delete" => self.delete(request),
            "insert" => self.insert(request),
            _ => ExtensionResponseEnum::Failure(format!(
                "Invalid table plugin action:{action:?} request:{request:?}"
            ))
            .into(),
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

impl TablePlugin {
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
                ExtensionResponseEnum::Failure(format!("Plugin error {e}").to_string()).into()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::_osquery::osquery;
    use crate::plugin::OsqueryPlugin;
    use column_def::ColumnOptions;

    // ==================== Test Mock: ReadOnlyTable ====================

    struct TestReadOnlyTable {
        test_name: String,
        test_columns: Vec<ColumnDef>,
        test_rows: Vec<BTreeMap<String, String>>,
    }

    impl TestReadOnlyTable {
        fn new(name: &str) -> Self {
            Self {
                test_name: name.to_string(),
                test_columns: vec![
                    ColumnDef::new("id", ColumnType::Integer, ColumnOptions::DEFAULT),
                    ColumnDef::new("value", ColumnType::Text, ColumnOptions::DEFAULT),
                ],
                test_rows: vec![],
            }
        }

        fn with_rows(mut self, rows: Vec<BTreeMap<String, String>>) -> Self {
            self.test_rows = rows;
            self
        }
    }

    impl ReadOnlyTable for TestReadOnlyTable {
        fn name(&self) -> String {
            self.test_name.clone()
        }

        fn columns(&self) -> Vec<ColumnDef> {
            self.test_columns.clone()
        }

        fn generate(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
            ExtensionResponse::new(
                osquery::ExtensionStatus {
                    code: Some(0),
                    message: Some("OK".to_string()),
                    uuid: None,
                },
                self.test_rows.clone(),
            )
        }

        fn shutdown(&self) {}
    }

    // ==================== Test Mock: Writeable Table ====================

    struct TestWriteableTable {
        test_name: String,
        test_columns: Vec<ColumnDef>,
        data: BTreeMap<u64, BTreeMap<String, String>>,
        next_id: u64,
    }

    impl TestWriteableTable {
        fn new(name: &str) -> Self {
            Self {
                test_name: name.to_string(),
                test_columns: vec![
                    ColumnDef::new("id", ColumnType::Integer, ColumnOptions::DEFAULT),
                    ColumnDef::new("value", ColumnType::Text, ColumnOptions::DEFAULT),
                ],
                data: BTreeMap::new(),
                next_id: 1,
            }
        }

        fn with_initial_row(mut self) -> Self {
            let mut row = BTreeMap::new();
            row.insert("id".to_string(), "1".to_string());
            row.insert("value".to_string(), "initial".to_string());
            self.data.insert(1, row);
            self.next_id = 2;
            self
        }
    }

    impl Table for TestWriteableTable {
        fn name(&self) -> String {
            self.test_name.clone()
        }

        fn columns(&self) -> Vec<ColumnDef> {
            self.test_columns.clone()
        }

        fn generate(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
            let rows: Vec<BTreeMap<String, String>> = self.data.values().cloned().collect();
            ExtensionResponse::new(
                osquery::ExtensionStatus {
                    code: Some(0),
                    message: Some("OK".to_string()),
                    uuid: None,
                },
                rows,
            )
        }

        fn update(&mut self, rowid: u64, row: &serde_json::Value) -> UpdateResult {
            use std::collections::btree_map::Entry;
            if let Entry::Occupied(mut entry) = self.data.entry(rowid) {
                let mut r = BTreeMap::new();
                r.insert("id".to_string(), rowid.to_string());
                if let Some(val) = row.get(1).and_then(|v| v.as_str()) {
                    r.insert("value".to_string(), val.to_string());
                }
                entry.insert(r);
                UpdateResult::Success
            } else {
                UpdateResult::Err("Row not found".to_string())
            }
        }

        fn delete(&mut self, rowid: u64) -> DeleteResult {
            if self.data.remove(&rowid).is_some() {
                DeleteResult::Success
            } else {
                DeleteResult::Err("Row not found".to_string())
            }
        }

        fn insert(&mut self, auto_rowid: bool, row: &serde_json::Value) -> InsertResult {
            let id = if auto_rowid {
                self.next_id
            } else {
                match row.get(0).and_then(|v| v.as_u64()) {
                    Some(id) => id,
                    None => self.next_id,
                }
            };
            let mut r = BTreeMap::new();
            r.insert("id".to_string(), id.to_string());
            if let Some(val) = row.get(1).and_then(|v| v.as_str()) {
                r.insert("value".to_string(), val.to_string());
            }
            self.data.insert(id, r);
            self.next_id = id + 1;
            InsertResult::Success(id)
        }

        fn shutdown(&self) {}
    }

    // ==================== ReadOnlyTable Tests ====================

    #[test]
    fn test_readonly_table_plugin_name() {
        let table = TestReadOnlyTable::new("test_table");
        let plugin = TablePlugin::from_readonly_table(table);
        assert_eq!(plugin.name(), "test_table");
    }

    #[test]
    fn test_readonly_table_plugin_columns() {
        let table = TestReadOnlyTable::new("test_table");
        let plugin = TablePlugin::from_readonly_table(table);
        let routes = plugin.routes();
        assert_eq!(routes.len(), 2); // id and value columns
        assert_eq!(
            routes.first().and_then(|r| r.get("name")),
            Some(&"id".to_string())
        );
        assert_eq!(
            routes.get(1).and_then(|r| r.get("name")),
            Some(&"value".to_string())
        );
    }

    #[test]
    fn test_readonly_table_plugin_generate() {
        let mut row = BTreeMap::new();
        row.insert("id".to_string(), "1".to_string());
        row.insert("value".to_string(), "test".to_string());
        let table = TestReadOnlyTable::new("test_table").with_rows(vec![row]);
        let plugin = TablePlugin::from_readonly_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "generate".to_string());
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(0));
        assert_eq!(response.response.as_ref().unwrap_or(&vec![]).len(), 1);
    }

    #[test]
    fn test_readonly_table_routes_via_handle_call() {
        let table = TestReadOnlyTable::new("test_table");
        let plugin = TablePlugin::from_readonly_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "columns".to_string());
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(0));
        assert_eq!(response.response.as_ref().unwrap_or(&vec![]).len(), 2); // 2 columns
    }

    #[test]
    fn test_readonly_table_registry() {
        let table = TestReadOnlyTable::new("test_table");
        let plugin = TablePlugin::from_readonly_table(table);
        assert_eq!(plugin.registry(), Registry::Table);
    }

    // ==================== Writeable Table Tests ====================

    #[test]
    fn test_writeable_table_plugin_name() {
        let table = TestWriteableTable::new("writeable_table");
        let plugin = TablePlugin::from_writeable_table(table);
        assert_eq!(plugin.name(), "writeable_table");
    }

    #[test]
    fn test_writeable_table_insert() {
        let table = TestWriteableTable::new("test_table");
        let plugin = TablePlugin::from_writeable_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "insert".to_string());
        req.insert("auto_rowid".to_string(), "true".to_string());
        req.insert(
            "json_value_array".to_string(),
            "[null, \"test_value\"]".to_string(),
        );
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(0)); // Success
    }

    #[test]
    fn test_writeable_table_update() {
        let table = TestWriteableTable::new("test_table").with_initial_row();
        let plugin = TablePlugin::from_writeable_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "update".to_string());
        req.insert("id".to_string(), "1".to_string());
        req.insert(
            "json_value_array".to_string(),
            "[1, \"updated\"]".to_string(),
        );
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(0)); // Success
    }

    #[test]
    fn test_writeable_table_delete() {
        let table = TestWriteableTable::new("test_table").with_initial_row();
        let plugin = TablePlugin::from_writeable_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "delete".to_string());
        req.insert("id".to_string(), "1".to_string());
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(0)); // Success
    }

    // ==================== Dispatch Tests ====================

    #[test]
    fn test_table_plugin_dispatch_readonly() {
        let table = TestReadOnlyTable::new("readonly");
        let plugin = TablePlugin::from_readonly_table(table);
        assert!(matches!(plugin, TablePlugin::Readonly(_)));
        assert_eq!(plugin.registry(), Registry::Table);
    }

    #[test]
    fn test_table_plugin_dispatch_writeable() {
        let table = TestWriteableTable::new("writeable");
        let plugin = TablePlugin::from_writeable_table(table);
        assert!(matches!(plugin, TablePlugin::Writeable(_)));
        assert_eq!(plugin.registry(), Registry::Table);
    }

    // ==================== Error Path Tests ====================

    #[test]
    fn test_readonly_table_insert_returns_readonly_error() {
        let table = TestReadOnlyTable::new("readonly");
        let plugin = TablePlugin::from_readonly_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "insert".to_string());
        req.insert("json_value_array".to_string(), "[1, \"test\"]".to_string());
        let response = plugin.handle_call(req);

        // Readonly error returns code 1 (see ExtensionResponseEnum::Readonly)
        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(1));
    }

    #[test]
    fn test_readonly_table_update_returns_readonly_error() {
        let table = TestReadOnlyTable::new("readonly");
        let plugin = TablePlugin::from_readonly_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "update".to_string());
        req.insert("id".to_string(), "1".to_string());
        req.insert("json_value_array".to_string(), "[1, \"test\"]".to_string());
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(1)); // Readonly error
    }

    #[test]
    fn test_readonly_table_delete_returns_readonly_error() {
        let table = TestReadOnlyTable::new("readonly");
        let plugin = TablePlugin::from_readonly_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "delete".to_string());
        req.insert("id".to_string(), "1".to_string());
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(1)); // Readonly error
    }

    #[test]
    fn test_invalid_action_returns_error() {
        let table = TestReadOnlyTable::new("test");
        let plugin = TablePlugin::from_readonly_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "invalid_action".to_string());
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(1)); // Failure
    }

    #[test]
    fn test_update_with_invalid_id_returns_error() {
        let table = TestWriteableTable::new("test");
        let plugin = TablePlugin::from_writeable_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "update".to_string());
        req.insert("id".to_string(), "not_a_number".to_string());
        req.insert("json_value_array".to_string(), "[1, \"test\"]".to_string());
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(1)); // Failure - cannot parse id
    }

    #[test]
    fn test_update_with_invalid_json_returns_error() {
        let table = TestWriteableTable::new("test");
        let plugin = TablePlugin::from_writeable_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "update".to_string());
        req.insert("id".to_string(), "1".to_string());
        req.insert("json_value_array".to_string(), "not valid json".to_string());
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(1)); // Failure - invalid JSON
    }

    #[test]
    fn test_insert_with_missing_json_returns_error() {
        let table = TestWriteableTable::new("test");
        let plugin = TablePlugin::from_writeable_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "insert".to_string());
        // Missing json_value_array
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(1)); // Failure
    }

    #[test]
    fn test_delete_with_missing_id_returns_error() {
        let table = TestWriteableTable::new("test");
        let plugin = TablePlugin::from_writeable_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "delete".to_string());
        // Missing id
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(1)); // Failure
    }

    #[test]
    fn test_delete_with_invalid_id_returns_error() {
        let table = TestWriteableTable::new("test");
        let plugin = TablePlugin::from_writeable_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "delete".to_string());
        req.insert("id".to_string(), "not_a_number".to_string());
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(1)); // Failure - cannot parse id
    }

    #[test]
    fn test_update_with_missing_id_returns_error() {
        let table = TestWriteableTable::new("test");
        let plugin = TablePlugin::from_writeable_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "update".to_string());
        req.insert("json_value_array".to_string(), "[1, \"test\"]".to_string());
        // Missing id
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(1)); // Failure
    }

    #[test]
    fn test_update_with_missing_json_returns_error() {
        let table = TestWriteableTable::new("test");
        let plugin = TablePlugin::from_writeable_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "update".to_string());
        req.insert("id".to_string(), "1".to_string());
        // Missing json_value_array
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(1)); // Failure
    }

    // ==================== Edge Case Tests ====================

    #[test]
    fn test_generate_with_empty_rows() {
        let table = TestReadOnlyTable::new("empty_table");
        let plugin = TablePlugin::from_readonly_table(table);

        let mut req = BTreeMap::new();
        req.insert("action".to_string(), "generate".to_string());
        let response = plugin.handle_call(req);

        let status = response.status.as_ref();
        assert!(status.is_some(), "response should have status");
        assert_eq!(status.and_then(|s| s.code), Some(0)); // Success with empty rows is valid
        assert_eq!(response.response.as_ref().unwrap_or(&vec![]).len(), 0);
    }

    #[test]
    fn test_ping_returns_default_status() {
        let table = TestReadOnlyTable::new("test");
        let plugin = TablePlugin::from_readonly_table(table);
        let status = plugin.ping();
        // Default ExtensionStatus should be valid
        assert!(status.code.is_none() || status.code == Some(0));
    }
}
