use log::info;
use osquery_rust_ng::plugin::{
    ColumnDef, ColumnOptions, ColumnType, DeleteResult, InsertResult, Table, UpdateResult,
};
use osquery_rust_ng::{ExtensionPluginRequest, ExtensionResponse, ExtensionStatus, ShutdownReason};
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

    fn generate(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
        let resp = BTreeMap::from([
            ("top".to_string(), "top".to_string()),
            ("bottom".to_string(), "bottom".to_string()),
        ]);

        ExtensionResponse::new(ExtensionStatus::default(), vec![resp])
    }

    fn update(&mut self, _rowid: u64, _row: &Value) -> UpdateResult {
        UpdateResult::Constraint
    }

    fn delete(&mut self, _rowid: u64) -> DeleteResult {
        DeleteResult::Err("Not yet implemented".to_string())
    }

    fn insert(&mut self, _auto_rowid: bool, _row: &Value) -> InsertResult {
        InsertResult::Constraint
    }

    fn shutdown(&self, reason: ShutdownReason) {
        info!("Table2 shutting down: {reason}");
    }
}
