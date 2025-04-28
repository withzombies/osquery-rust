use osquery_rust::plugin::{
    ColumnDef, ColumnOptions, ColumnType, DeleteResult, InsertResult, ReadOnlyTable, Table,
    UpdateResult,
};
use osquery_rust::{ExtensionPluginRequest, ExtensionResponse, ExtensionStatus};
use serde_json::Value;
use std::collections::BTreeMap;
use std::process::exit;

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

    fn generate(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        let resp = BTreeMap::from([
            ("top".to_string(), "top".to_string()),
            ("bottom".to_string(), "bottom".to_string()),
        ]);

        ExtensionResponse::new(ExtensionStatus::default(), vec![resp])
    }

    fn update(&mut self, rowid: u64, row: &Value) -> UpdateResult {
        UpdateResult::Constraint
    }

    fn delete(&mut self, rowid: u64) -> DeleteResult {
        DeleteResult::Err("Not yet implemented".to_string())
    }

    fn insert(&mut self, auto_rowid: bool, row: &Value) -> InsertResult {
        InsertResult::Constraint
    }

    fn shutdown(&self) {
        exit(0)
    }
}
