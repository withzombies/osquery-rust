/// Request handling logic for table operations
use crate::_osquery::ExtensionPluginRequest;
use crate::plugin::_enums::response::ExtensionResponseEnum;
use crate::plugin::table::results::{DeleteResult, InsertResult, UpdateResult};
use crate::plugin::table::table_plugin::TablePlugin;
use crate::ExtensionResponse;
use serde_json::Value;

impl TablePlugin {
    /// Parse and handle incoming requests
    pub fn parse_request(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        let action = req.get("action").map(|s| s.as_str()).unwrap_or("");

        match action {
            "generate" => self.generate(req),
            "update" => self.update(req),
            "delete" => self.delete(req),
            "insert" => self.insert(req),
            _ => ExtensionResponseEnum::Failure(format!("Unknown action: {action}")).into(),
        }
    }

    fn generate(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        match self {
            TablePlugin::Writeable(table) => {
                let Ok(mut table) = table.lock() else {
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

        match table.update(id.to_string(), row) {
            UpdateResult::Ok => ExtensionResponseEnum::Success().into(),
            UpdateResult::NotFound => ExtensionResponseEnum::Constraint().into(),
            UpdateResult::Error(err) => ExtensionResponseEnum::Failure(err).into(),
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

        match table.delete(id.to_string()) {
            DeleteResult::Ok => ExtensionResponseEnum::Success().into(),
            DeleteResult::NotFound => ExtensionResponseEnum::Constraint().into(),
            DeleteResult::Error(e) => {
                ExtensionResponseEnum::Failure(format!("Plugin error: {e}")).into()
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

        match table.insert(row) {
            InsertResult::Ok(id) => {
                // Try to parse the ID as u64, fallback to 0 if it fails
                let id_num = id.parse::<u64>().unwrap_or(0);
                ExtensionResponseEnum::SuccessWithId(id_num).into()
            }
            InsertResult::Error(err) => ExtensionResponseEnum::Failure(err).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::table::column_def::{ColumnDef, ColumnOptions, ColumnType};
    use crate::plugin::table::traits::{ReadOnlyTable, Table};
    use crate::_osquery::ExtensionStatus;
    use std::collections::HashMap;

    struct TestTable {
        data: HashMap<String, Value>,
        next_id: u32,
    }

    impl Default for TestTable {
        fn default() -> Self {
            Self {
                data: HashMap::new(),
                next_id: 1,
            }
        }
    }

    impl Table for TestTable {
        fn name(&self) -> String {
            "test_table".to_string()
        }

        fn columns(&self) -> Vec<ColumnDef> {
            vec![ColumnDef::new("id", ColumnType::Text, ColumnOptions::empty())]
        }

        fn generate(&mut self, _request: ExtensionPluginRequest) -> ExtensionResponse {
            ExtensionResponse::new(ExtensionStatus::new(0, None, None), vec![])
        }

        fn insert(&mut self, json: Value) -> InsertResult {
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

        fn update(&mut self, id: String, json: Value) -> UpdateResult {
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
            "readonly_test".to_string()
        }

        fn columns(&self) -> Vec<ColumnDef> {
            vec![ColumnDef::new("col", ColumnType::Text, ColumnOptions::empty())]
        }

        fn generate(&self, _request: ExtensionPluginRequest) -> ExtensionResponse {
            ExtensionResponse::new(ExtensionStatus::new(0, None, None), vec![])
        }

        fn shutdown(&self) {}
    }

    #[test]
    fn test_generate_with_empty_rows() {
        let plugin = TablePlugin::from_writeable_table(TestTable::default());
        let mut request = ExtensionPluginRequest::new();
        request.insert("action".to_string(), "generate".to_string());

        let response = plugin.parse_request(request);
        assert_eq!(response.status.unwrap().code, Some(0));
    }

    #[test]
    fn test_insert_with_missing_json_returns_error() {
        let plugin = TablePlugin::from_writeable_table(TestTable::default());
        let mut request = ExtensionPluginRequest::new();
        request.insert("action".to_string(), "insert".to_string());

        let response = plugin.parse_request(request);
        assert_eq!(response.status.unwrap().code, Some(1));
    }

    #[test]
    fn test_readonly_table_insert_returns_readonly_error() {
        let plugin = TablePlugin::from_readonly_table(TestReadOnlyTable);
        let mut request = ExtensionPluginRequest::new();
        request.insert("action".to_string(), "insert".to_string());

        let response = plugin.parse_request(request);
        let status = response.status.as_ref().unwrap();
        assert_eq!(status.code, Some(1));
        assert!(status.message.as_ref().unwrap().contains("read-only"));
    }

    #[test]
    fn test_invalid_action_returns_error() {
        let plugin = TablePlugin::from_readonly_table(TestReadOnlyTable);
        let mut request = ExtensionPluginRequest::new();
        request.insert("action".to_string(), "invalid_action".to_string());

        let response = plugin.parse_request(request);
        assert_eq!(response.status.unwrap().code, Some(1));
    }
}