/// Table trait definitions for readonly and writeable tables
use crate::_osquery::ExtensionPluginRequest;
use crate::plugin::table::column_def::ColumnDef;
use crate::plugin::table::results::{DeleteResult, InsertResult, UpdateResult};
use crate::ExtensionResponse;

/// Trait for writeable tables that support insert, update, delete operations
pub trait Table: Send + Sync + 'static {
    fn name(&self) -> String;
    fn columns(&self) -> Vec<ColumnDef>;
    fn generate(&mut self, request: ExtensionPluginRequest) -> ExtensionResponse;
    fn insert(&mut self, json: serde_json::Value) -> InsertResult;
    fn delete(&mut self, id: String) -> DeleteResult;
    fn update(&mut self, id: String, json: serde_json::Value) -> UpdateResult;
    fn shutdown(&self);
}

/// Trait for read-only tables that only support query operations
pub trait ReadOnlyTable: Send + Sync + 'static {
    fn name(&self) -> String;
    fn columns(&self) -> Vec<ColumnDef>;
    fn generate(&self, request: ExtensionPluginRequest) -> ExtensionResponse;
    fn shutdown(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::_osquery::ExtensionStatus;
    use crate::plugin::table::column_def::{ColumnDef, ColumnOptions, ColumnType};
    use std::collections::HashMap;

    struct TestWriteableTable {
        data: HashMap<String, serde_json::Value>,
        next_id: u32,
    }

    impl Default for TestWriteableTable {
        fn default() -> Self {
            Self {
                data: HashMap::new(),
                next_id: 1,
            }
        }
    }

    impl Table for TestWriteableTable {
        fn name(&self) -> String {
            "test_writeable_table".to_string()
        }

        fn columns(&self) -> Vec<ColumnDef> {
            vec![
                ColumnDef::new("id", ColumnType::Text, ColumnOptions::empty()),
                ColumnDef::new("data", ColumnType::Text, ColumnOptions::empty()),
            ]
        }

        fn generate(&mut self, _request: ExtensionPluginRequest) -> ExtensionResponse {
            ExtensionResponse::new(ExtensionStatus::new(0, None, None), vec![])
        }

        fn insert(&mut self, json: serde_json::Value) -> InsertResult {
            let id = self.next_id.to_string();
            self.next_id += 1;
            self.data.insert(id.clone(), json);
            InsertResult::Ok(id)
        }

        fn delete(&mut self, id: String) -> DeleteResult {
            if self.data.remove(&id).is_some() {
                DeleteResult::Ok
            } else {
                DeleteResult::NotFound
            }
        }

        fn update(&mut self, id: String, json: serde_json::Value) -> UpdateResult {
            if self.data.contains_key(&id) {
                self.data.insert(id, json);
                UpdateResult::Ok
            } else {
                UpdateResult::NotFound
            }
        }

        fn shutdown(&self) {}
    }

    struct TestReadOnlyTable;

    impl ReadOnlyTable for TestReadOnlyTable {
        fn name(&self) -> String {
            "test_readonly_table".to_string()
        }

        fn columns(&self) -> Vec<ColumnDef> {
            vec![ColumnDef::new(
                "test_column",
                ColumnType::Text,
                ColumnOptions::empty(),
            )]
        }

        fn generate(&self, _request: ExtensionPluginRequest) -> ExtensionResponse {
            ExtensionResponse::new(ExtensionStatus::new(0, None, None), vec![])
        }

        fn shutdown(&self) {}
    }

    #[test]
    fn test_writeable_table_insert() {
        let mut table = TestWriteableTable::default();
        let json = serde_json::json!({"name": "test"});

        match table.insert(json) {
            InsertResult::Ok(id) => assert_eq!(id, "1"),
            _ => panic!("Insert should succeed"),
        }
    }

    #[test]
    fn test_writeable_table_delete() {
        let mut table = TestWriteableTable::default();
        let json = serde_json::json!({"name": "test"});

        if let InsertResult::Ok(id) = table.insert(json) {
            assert_eq!(table.delete(id), DeleteResult::Ok);
        }
    }

    #[test]
    fn test_writeable_table_update() {
        let mut table = TestWriteableTable::default();
        let json = serde_json::json!({"name": "test"});

        if let InsertResult::Ok(id) = table.insert(json) {
            let new_json = serde_json::json!({"name": "updated"});
            assert_eq!(table.update(id, new_json), UpdateResult::Ok);
        }
    }

    #[test]
    fn test_readonly_table_generate() {
        let table = TestReadOnlyTable;
        let response = table.generate(Default::default());
        assert_eq!(response.status.as_ref().unwrap().code, Some(0));
    }
}
