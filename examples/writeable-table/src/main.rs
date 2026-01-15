mod cli;

use crate::cli::Args;
use clap::{Parser, crate_name};
use log::info;
use osquery_rust_ng::plugin::{ColumnDef, ColumnOptions, ColumnType, Plugin, Table};
use osquery_rust_ng::plugin::{DeleteResult, InsertResult, UpdateResult};
use osquery_rust_ng::{ExtensionPluginRequest, ExtensionResponse, ExtensionStatus, Server};
use std::collections::BTreeMap;
use std::io::{Error, ErrorKind};

struct WriteableTable {
    items: BTreeMap<String, (String, String)>,
    next_id: u64,
}

impl WriteableTable {
    fn new() -> Self {
        Self {
            items: vec!["foo".to_string(), "bar".to_string(), "baz".to_string()]
                .into_iter()
                .enumerate()
                .map(|(idx, item)| (idx.to_string(), (item.clone(), item.clone())))
                .collect(),
            next_id: 3,
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

    fn generate(&mut self, _req: ExtensionPluginRequest) -> ExtensionResponse {
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

    fn update(&mut self, rowid: String, row: serde_json::Value) -> UpdateResult {
        log::info!("updating item at {rowid} = {row:?}");

        let Some(row_array) = row.as_array() else {
            return UpdateResult::Error("Could not parse row as array".to_string());
        };

        if row_array.len() < 2 {
            return UpdateResult::Error("Row must have at least 2 elements".to_string());
        }

        let Some(name) = row_array.first().and_then(|v| v.as_str()) else {
            return UpdateResult::Error("Name must be a string".to_string());
        };

        let Some(lastname) = row_array.get(1).and_then(|v| v.as_str()) else {
            return UpdateResult::Error("Lastname must be a string".to_string());
        };

        if let std::collections::btree_map::Entry::Occupied(mut e) = self.items.entry(rowid) {
            e.insert((name.to_string(), lastname.to_string()));
            UpdateResult::Ok
        } else {
            UpdateResult::NotFound
        }
    }

    fn delete(&mut self, rowid: String) -> DeleteResult {
        log::info!("deleting item: {rowid}");

        match self.items.remove(&rowid) {
            Some(_) => DeleteResult::Ok,
            None => DeleteResult::NotFound,
        }
    }

    fn insert(&mut self, row: serde_json::Value) -> InsertResult {
        log::info!("inserting item: {row:?}");

        let Some(row_array) = row.as_array() else {
            return InsertResult::Error("Could not parse row as array".to_string());
        };

        if row_array.len() < 2 {
            return InsertResult::Error("Row must have at least 2 elements".to_string());
        }

        let Some(name) = row_array.first().and_then(|v| v.as_str()) else {
            return InsertResult::Error("Name must be a string".to_string());
        };

        let Some(lastname) = row_array.get(1).and_then(|v| v.as_str()) else {
            return InsertResult::Error("Lastname must be a string".to_string());
        };

        let rowid = self.next_id.to_string();
        self.next_id += 1;

        self.items
            .insert(rowid.clone(), (name.to_string(), lastname.to_string()));

        InsertResult::Ok(rowid)
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
        let mut table = WriteableTable::new();
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

        // Insert new row (auto-assign rowid)
        let row = json!(["alice", "smith"]);
        let result = table.insert(row);

        let InsertResult::Ok(rowid) = result else {
            panic!("Expected InsertResult::Ok");
        };
        assert_eq!(rowid, "3"); // Next after 0, 1, 2

        // Verify the row was added
        let response = table.generate(ExtensionPluginRequest::default());
        let rows = response.response.expect("should have rows");
        assert_eq!(rows.len(), 4);
    }

    #[test]
    fn test_insert_another_row() {
        let mut table = WriteableTable::new();

        // Insert another row
        let row = json!(["bob", "jones"]);
        let result = table.insert(row);

        let InsertResult::Ok(rowid) = result else {
            panic!("Expected InsertResult::Ok");
        };
        assert_eq!(rowid, "3");
    }

    #[test]
    fn test_insert_invalid_row_returns_error() {
        let mut table = WriteableTable::new();

        // Invalid row format
        let row = json!(["invalid"]);
        let result = table.insert(row);

        assert!(matches!(result, InsertResult::Error(_)));
    }

    #[test]
    fn test_update_existing_row() {
        let mut table = WriteableTable::new();

        // Update row 0 (foo -> updated)
        let row = json!(["updated_name", "updated_lastname"]);
        let result = table.update("0".to_string(), row);

        assert!(matches!(result, UpdateResult::Ok));

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
        let result = table.update("0".to_string(), row);

        assert!(matches!(result, UpdateResult::Error(_)));
    }

    #[test]
    fn test_delete_existing_row() {
        let mut table = WriteableTable::new();

        // Delete row 0
        let result = table.delete("0".to_string());
        assert!(matches!(result, DeleteResult::Ok));

        // Verify deletion
        let response = table.generate(ExtensionPluginRequest::default());
        let rows = response.response.expect("should have rows");
        assert_eq!(rows.len(), 2); // 3 - 1 = 2
    }

    #[test]
    fn test_delete_nonexistent_row_returns_error() {
        let mut table = WriteableTable::new();

        // Try to delete non-existent row
        let result = table.delete("999".to_string());

        assert!(matches!(result, DeleteResult::NotFound));
    }

    #[test]
    fn test_full_crud_workflow() {
        let mut table = WriteableTable::new();

        // Create
        let row = json!(["new_user", "new_lastname"]);
        let InsertResult::Ok(new_rowid) = table.insert(row) else {
            panic!("Insert failed");
        };

        // Read (verify exists)
        let response = table.generate(ExtensionPluginRequest::default());
        let rows = response.response.expect("should have rows");
        assert_eq!(rows.len(), 4);

        // Update
        let updated = json!(["modified", "user"]);
        assert!(matches!(
            table.update(new_rowid.clone(), updated),
            UpdateResult::Ok
        ));

        // Delete
        assert!(matches!(table.delete(new_rowid), DeleteResult::Ok));

        // Verify final state
        let response = table.generate(ExtensionPluginRequest::default());
        let rows = response.response.expect("should have rows");
        assert_eq!(rows.len(), 3); // Back to original count
    }
}
