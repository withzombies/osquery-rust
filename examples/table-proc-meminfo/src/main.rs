mod cli;

use clap::crate_name;
use clap::Parser;
use log::info;
use osquery_rust_ng::plugin::{ColumnDef, ColumnOptions, ColumnType, Plugin, ReadOnlyTable};
use osquery_rust_ng::prelude::*;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Error, ErrorKind};

use crate::cli::Args;
use regex::Regex;

#[derive(Debug, Clone)]
struct ProcMemInfoTable {}

impl ReadOnlyTable for ProcMemInfoTable {
    fn name(&self) -> String {
        "proc_meminfo".to_string()
    }

    fn columns(&self) -> Vec<ColumnDef> {
        let mut columns: Vec<ColumnDef> = Vec::new();
        let Ok(regex) = Regex::new(r"(?P<label>\S+):") else {
            return vec![];
        };

        let f = match File::open("/proc/meminfo") {
            Ok(f) => f,
            Err(e) => {
                println!("Error opening file: {e}");
                return vec![];
            }
        };

        let reader = BufReader::new(f);

        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(e) => {
                    println!("Error reading line: {e}");
                    continue;
                }
            };

            if let Some(cap) = regex.captures(line.as_str()) {
                if cap.len() != 2 {
                    continue;
                }
                let s = cap[1].replace('(', "_").replace(')', "");
                columns.push(ColumnDef::new(
                    s.to_lowercase().as_str(),
                    ColumnType::BigInt,
                    ColumnOptions::DEFAULT,
                ));
            }
        }

        columns
    }

    fn generate(&self, _req: ExtensionPluginRequest) -> ExtensionResponse {
        let resp = vec![self.proc_meminfo()];
        ExtensionResponse::new(ExtensionStatus::default(), resp)
    }

    fn shutdown(&self) {
        info!("Shutting down");
    }
}

impl ProcMemInfoTable {
    fn proc_meminfo(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        let Ok(regex) = Regex::new(r"(?P<label>\S+):\s+(?P<number>\d+)") else {
            return map;
        };

        let f = match File::open("/proc/meminfo") {
            Ok(x) => x,
            Err(e) => {
                println!("Error opening file: {e}");
                return map;
            }
        };
        let reader = BufReader::new(f);

        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(e) => {
                    println!("Error reading line: {e}");
                    continue;
                }
            };

            let Some(cap) = regex.captures(line.as_str()) else {
                continue;
            };

            if cap.len() != 3 {
                continue;
            }
            let s = cap[1].replace('(', "_").replace(')', "");
            map.insert(s.to_lowercase(), cap[2].to_string());
        }

        map
    }
}

fn main() -> std::io::Result<()> {
    env_logger::init();

    let args = Args::parse();

    // todo: handle non existing socket gracefully
    if !args.standalone() {
        let Some(socket) = args.socket() else {
            return Err(Error::new(ErrorKind::InvalidInput, "No socket provided"));
        };

        let mut manager = Server::new(Some(crate_name!()), socket.as_str())?;

        manager.register_plugin(Plugin::readonly_table(ProcMemInfoTable {}));

        manager.run().map_err(Error::other)?;
    } else {
        todo!("standalone mode has not been implemented");
    }

    Ok(())
}
