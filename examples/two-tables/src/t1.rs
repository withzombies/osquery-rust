use osquery_rust_ng::plugin::{ColumnDef, ColumnOptions, ColumnType, ReadOnlyTable};
use osquery_rust_ng::{ExtensionPluginRequest, ExtensionResponse, ExtensionStatus};
use std::collections::BTreeMap;
use std::process::exit;

pub struct Table1 {}

impl Table1 {
    pub fn new() -> Self {
        Table1 {}
    }
}

impl ReadOnlyTable for Table1 {
    fn name(&self) -> String {
        "t1".to_string()
    }

    fn columns(&self) -> Vec<ColumnDef> {
        vec![
            ColumnDef::new("left", ColumnType::Text, ColumnOptions::DEFAULT),
            ColumnDef::new("right", ColumnType::Text, ColumnOptions::DEFAULT),
        ]
    }

    fn generate(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
        let resp = BTreeMap::from([
            ("left".to_string(), "left".to_string()),
            ("right".to_string(), "right".to_string()),
        ]);

        ExtensionResponse::new(ExtensionStatus::default(), vec![resp])
    }

    fn shutdown(&self) {
        exit(0)
    }
}
