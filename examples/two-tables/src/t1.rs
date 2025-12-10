use log::info;
use osquery_rust_ng::plugin::{ColumnDef, ColumnOptions, ColumnType, ReadOnlyTable};
use osquery_rust_ng::{ExtensionPluginRequest, ExtensionResponse, ExtensionStatus};
use std::collections::BTreeMap;

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
        info!("Table1 shutting down");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_table1_name() {
        let table = Table1::new();
        assert_eq!(table.name(), "t1");
    }

    #[test]
    fn test_table1_columns() {
        let table = Table1::new();
        let cols = table.columns();
        assert_eq!(cols.len(), 2);
    }

    #[test]
    fn test_table1_generate() {
        let table = Table1::new();
        let response = table.generate(ExtensionPluginRequest::default());
        let rows = response.response.expect("should have rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("left"), Some(&"left".to_string()));
        assert_eq!(rows[0].get("right"), Some(&"right".to_string()));
    }
}
