mod cli;

use crate::cli::Args;
use clap::{Parser, crate_name};
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
        log::info!("shutting down");
        std::process::exit(0);
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
