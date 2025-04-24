mod cli;

use crate::cli::Args;
use clap::{Parser, crate_name};
use osquery_rust::plugin::{
    ColumnDef, ColumnOptions, ColumnType, Plugin, Table, create_readonly_response,
};
use osquery_rust::{ExtensionPluginRequest, ExtensionResponse, ExtensionStatus, Server};
use std::collections::BTreeMap;
use std::io::{Error, ErrorKind};

struct WriteableTable {
    items: Vec<String>,
}

impl WriteableTable {
    fn new() -> Self {
        Self {
            items: vec!["foo".to_string(), "bar".to_string(), "baz".to_string()],
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
        ]
    }

    fn select(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
        let resp = self
            .items
            .iter()
            .enumerate()
            .map(|(idx, item)| {
                BTreeMap::from([
                    ("rowid".to_string(), idx.to_string()),
                    ("name".to_string(), item.clone()),
                ])
            })
            .collect::<Vec<_>>();

        ExtensionResponse::new(ExtensionStatus::default(), resp)
    }

    fn update(&mut self, _req: ExtensionPluginRequest) -> ExtensionResponse {
        create_readonly_response()
    }

    fn delete(&mut self, id: u64) -> Result<(), Error> {
        log::info!("deleting item: {}", id);

        self.items.remove(id as usize);

        Ok(())
    }

    fn insert(&mut self, _req: ExtensionPluginRequest) -> ExtensionResponse {
        create_readonly_response()
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
