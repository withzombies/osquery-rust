use log::info;
use osquery_rust_ng::plugin::{
    ColumnDef, ColumnOptions, ColumnType, DeleteResult, InsertResult, Table, UpdateResult,
};
use osquery_rust_ng::{ExtensionPluginRequest, ExtensionResponse, ExtensionStatus};
use serde_json::Value;
use std::collections::BTreeMap;

pub struct Table2 {}

impl Table2 {
    pub fn new() -> Self {
        Table2 {}
    }
}

impl Table for Table2 {
    fn name(&self) -> String {
        "t2".to_string()
    }

    fn columns(&self) -> Vec<ColumnDef> {
        vec![
            ColumnDef::new("top", ColumnType::Text, ColumnOptions::DEFAULT),
            ColumnDef::new("bottom", ColumnType::Text, ColumnOptions::DEFAULT),
        ]
    }

    fn generate(&mut self, _req: ExtensionPluginRequest) -> ExtensionResponse {
        let resp = BTreeMap::from([
            ("top".to_string(), "top".to_string()),
            ("bottom".to_string(), "bottom".to_string()),
        ]);

        ExtensionResponse::new(ExtensionStatus::default(), vec![resp])
    }

    fn update(&mut self, _rowid: String, _row: serde_json::Value) -> UpdateResult {
        UpdateResult::Error("Table t2 is read-only".to_string())
    }

    fn delete(&mut self, _rowid: String) -> DeleteResult {
        DeleteResult::Error("Table t2 is read-only".to_string())
    }

    fn insert(&mut self, _row: serde_json::Value) -> InsertResult {
        InsertResult::Error("Table t2 is read-only".to_string())
    }

    fn shutdown(&self) {
        info!("Table2 shutting down");
    }
}
