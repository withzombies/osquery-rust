mod cli;

use crate::cli::Args;
use clap::{Parser, crate_name};
use log::info;
use osquery_rust_ng::plugin::{ColumnDef, ColumnOptions, ColumnType, Plugin, Table};
use osquery_rust_ng::plugin::{DeleteResult, InsertResult, UpdateResult};
use osquery_rust_ng::{ExtensionPluginRequest, ExtensionResponse, ExtensionStatus, Server};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{Error, ErrorKind};

struct WriteableTable {
    items: BTreeMap<u64, (String, String)>,
}

impl WriteableTable {
    fn new() -> Self {
        Self {
            items: vec!["foo".to_string(), "bar".to_string(), "baz".to_string()]
                .into_iter()
                .enumerate()
                .map(|(idx, item)| (idx as u64, (item.clone(), item.clone())))
                .collect(),
        }
    }
}

impl Table for WriteableTable {
    fn name(&self) -> String {
        "writeable_table".to_string()
    }

    fn columns(&self) -> Vec<ColumnDef> {
        vec![
            ColumnDef::new(
                "rowid",
                ColumnType::Integer,
                ColumnOptions::INDEX | ColumnOptions::HIDDEN,
            ),
            ColumnDef::new("name", ColumnType::Text, ColumnOptions::DEFAULT),
            ColumnDef::new("lastname", ColumnType::Text, ColumnOptions::DEFAULT),
        ]
    }

    fn generate(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
        let resp = self
            .items
            .iter()
            .map(|(idx, item)| {
                BTreeMap::from([
                    ("rowid".to_string(), idx.to_string()),
                    ("name".to_string(), item.0.clone()),
                    ("lastname".to_string(), item.1.clone()),
                ])
            })
            .collect::<Vec<_>>();

        ExtensionResponse::new(ExtensionStatus::default(), resp)
    }

    fn update(&mut self, rowid: u64, row: &Value) -> UpdateResult {
        log::info!("updating item at {rowid} = {row:?}");

        let Some(row) = row.as_array() else {
            return UpdateResult::Err("Could not parse row as array".to_string());
        };

        let &[
            Value::Number(rowid),
            Value::String(name),
            Value::String(lastname),
        ] = &row.as_slice()
        else {
            return UpdateResult::Err("Could not parse row update".to_string());
        };

        let Some(rowid) = rowid.as_u64() else {
            return UpdateResult::Err("Could not parse rowid as u64".to_string());
        };

        self.items.insert(rowid, (name.clone(), lastname.clone()));

        UpdateResult::Success
    }

    fn delete(&mut self, rowid: u64) -> DeleteResult {
        log::info!("deleting item: {rowid}");

        match self.items.remove(&rowid) {
            Some(_) => DeleteResult::Success,
            None => DeleteResult::Err("Could not find rowid".to_string()),
        }
    }

    fn insert(&mut self, _auto_rowid: bool, row: &Value) -> InsertResult {
        log::info!("inserting item: {row:?}");

        let Some(row) = row.as_array() else {
            return InsertResult::Err("Could not parse row as array".to_string());
        };

        let rowid = match &row.as_slice() {
            [Value::Null, Value::String(name), Value::String(lastname)] => {
                // TODO: figure out what auto_rowid means here
                let rowid = self.items.keys().next_back().unwrap_or(&0u64) + 1;
                log::info!("rowid: {rowid}");

                self.items.insert(rowid, (name.clone(), lastname.clone()));

                rowid
            }
            [
                Value::Number(rowid),
                Value::String(name),
                Value::String(lastname),
            ] => {
                let Some(rowid) = rowid.as_u64() else {
                    return InsertResult::Err("Could not parse rowid as u64".to_string());
                };

                self.items.insert(rowid, (name.clone(), lastname.clone()));

                rowid
            }
            _ => {
                return InsertResult::Constraint;
            }
        };

        InsertResult::Success(rowid)
    }
    fn shutdown(&self) {
        info!("Shutting down");
    }
}

fn main() -> std::io::Result<()> {
    env_logger::init();

    let args = Args::parse();

    if !args.standalone() {
        let Some(socket) = args.socket() else {
            return Err(Error::new(ErrorKind::InvalidInput, "No socket provided"));
        };

        let mut manager = Server::new(Some(crate_name!()), socket.as_str())?;

        manager.register_plugin(Plugin::table(WriteableTable::new()));

        manager.run().map_err(Error::other)?;
    } else {
        todo!("standalone mode has not been implemented");
    }

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_table_name() {
        let table = WriteableTable::new();
        assert_eq!(table.name(), "writeable_table");
    }

    #[test]
    fn test_table_columns() {
        let table = WriteableTable::new();
        let cols = table.columns();
        assert_eq!(cols.len(), 3);
    }

    #[test]
    fn test_generate_returns_initial_data() {
        let table = WriteableTable::new();
        let response = table.generate(ExtensionPluginRequest::default());
        let rows = response.response.expect("should have rows");

        // Initial data: foo, bar, baz
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].get("name"), Some(&"foo".to_string()));
        assert_eq!(rows[1].get("name"), Some(&"bar".to_string()));
        assert_eq!(rows[2].get("name"), Some(&"baz".to_string()));
    }

    #[test]
    fn test_insert_with_auto_rowid() {
        let mut table = WriteableTable::new();

        // Insert with null rowid (auto-assign)
        let row = json!([null, "alice", "smith"]);
        let result = table.insert(true, &row);

        let InsertResult::Success(rowid) = result else {
            panic!("Expected InsertResult::Success");
        };
        assert_eq!(rowid, 3); // Next after 0, 1, 2

        // Verify the row was added
        let response = table.generate(ExtensionPluginRequest::default());
        let rows = response.response.expect("should have rows");
        assert_eq!(rows.len(), 4);
    }

    #[test]
    fn test_insert_with_explicit_rowid() {
        let mut table = WriteableTable::new();

        // Insert with explicit rowid
        let row = json!([100, "bob", "jones"]);
        let result = table.insert(false, &row);

        let InsertResult::Success(rowid) = result else {
            panic!("Expected InsertResult::Success");
        };
        assert_eq!(rowid, 100);
    }

    #[test]
    fn test_insert_invalid_row_returns_constraint() {
        let mut table = WriteableTable::new();

        // Invalid row format
        let row = json!(["invalid"]);
        let result = table.insert(false, &row);

        assert!(matches!(result, InsertResult::Constraint));
    }

    #[test]
    fn test_update_existing_row() {
        let mut table = WriteableTable::new();

        // Update row 0 (foo -> updated)
        let row = json!([0, "updated_name", "updated_lastname"]);
        let result = table.update(0, &row);

        assert!(matches!(result, UpdateResult::Success));

        // Verify the update
        let response = table.generate(ExtensionPluginRequest::default());
        let rows = response.response.expect("should have rows");
        let row0 = rows
            .iter()
            .find(|r| r.get("rowid") == Some(&"0".to_string()));
        assert_eq!(row0.unwrap().get("name"), Some(&"updated_name".to_string()));
    }

    #[test]
    fn test_update_invalid_row_returns_error() {
        let mut table = WriteableTable::new();

        // Invalid row (not an array)
        let row = json!({"name": "test"});
        let result = table.update(0, &row);

        assert!(matches!(result, UpdateResult::Err(_)));
    }

    #[test]
    fn test_delete_existing_row() {
        let mut table = WriteableTable::new();

        // Delete row 0
        let result = table.delete(0);
        assert!(matches!(result, DeleteResult::Success));

        // Verify deletion
        let response = table.generate(ExtensionPluginRequest::default());
        let rows = response.response.expect("should have rows");
        assert_eq!(rows.len(), 2); // 3 - 1 = 2
    }

    #[test]
    fn test_delete_nonexistent_row_returns_error() {
        let mut table = WriteableTable::new();

        // Try to delete non-existent row
        let result = table.delete(999);

        assert!(matches!(result, DeleteResult::Err(_)));
    }

    #[test]
    fn test_full_crud_workflow() {
        let mut table = WriteableTable::new();

        // Create
        let row = json!([null, "new_user", "new_lastname"]);
        let InsertResult::Success(new_rowid) = table.insert(true, &row) else {
            panic!("Insert failed");
        };

        // Read (verify exists)
        let response = table.generate(ExtensionPluginRequest::default());
        let rows = response.response.expect("should have rows");
        assert_eq!(rows.len(), 4);

        // Update
        let updated = json!([new_rowid, "modified", "user"]);
        assert!(matches!(
            table.update(new_rowid, &updated),
            UpdateResult::Success
        ));

        // Delete
        assert!(matches!(table.delete(new_rowid), DeleteResult::Success));

        // Verify final state
        let response = table.generate(ExtensionPluginRequest::default());
        let rows = response.response.expect("should have rows");
        assert_eq!(rows.len(), 3); // Back to original count
    }
}
