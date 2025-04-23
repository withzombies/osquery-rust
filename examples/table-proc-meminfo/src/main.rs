use clap::crate_name;
use clap::Parser;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

use osquery_rust::plugin::{ColumnDef, ColumnType, Plugin, Table};
use osquery_rust::prelude::*;

use regex::Regex;

#[derive(clap::Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(arg_required_else_help = true)]
#[clap(group(
  clap::ArgGroup::new("mode")
    .required(true)
    .multiple(false)
    .args(&["standalone", "socket"]),
))]
#[clap(group(
  clap::ArgGroup::new("mode::socket")
    .required(false)
    .multiple(true)
    .conflicts_with("standalone")
    .args(&["interval", "timeout"]),
))]
pub struct Args {
    // Operating in standalone mode
    #[clap(long)]
    standalone: bool,

    // Operating in socket mode
    #[clap(long, value_name = "PATH_TO_SOCKET")]
    socket: Option<String>,

    /// Delay in seconds between connectivity checks.
    #[clap(long, default_value_t = 30)]
    interval: u32,

    /// Time in seconds to wait for autoloaded extensions until connection times out.
    #[clap(long, default_value_t = 30)]
    timeout: u32,

    /// Enable verbose informational messages.
    #[clap(long)]
    verbose: bool,
}

impl Args {
    pub fn standalone(&self) -> bool {
        self.standalone
    }

    pub fn socket(&self) -> Option<String> {
        self.socket.clone()
    }
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    // todo: handle non existing socket gracefully
    if !args.standalone {
        let mut manager = Server::new(Some(crate_name!()), args.socket().unwrap().as_str())?;

        manager.register_plugin(Plugin::Table(Table::new(
            "proc_meminfo",
            columns(),
            generate,
        )));

        manager.run();
    } else {
        todo!("standalone mode has not been implemented");
    }

    Ok(())
}

fn columns() -> Vec<ColumnDef> {
    let mut columns: Vec<ColumnDef> = Vec::new();
    let regex = Regex::new(r"(?P<label>\S+):").unwrap();

    let f = File::open("/proc/meminfo").unwrap();
    let reader = BufReader::new(f);

    for line in reader.lines() {
        let s: String = line.unwrap();

        let cap = regex.captures(s.as_str()).unwrap();
        let s = cap[1].replace('(', "_").replace(')', "");
        columns.push(ColumnDef::new(
            s.to_lowercase().as_str(),
            ColumnType::BigInt,
        ));
    }

    columns
}

fn generate(_req: ExtensionPluginRequest) -> ExtensionResponse {
    let resp = vec![proc_meminfo()];
    ExtensionResponse::new(ExtensionStatus::default(), resp)
}

fn proc_meminfo() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let regex = Regex::new(r"(?P<label>\S+):\s+(?P<number>\d+)").unwrap();

    let f = File::open("/proc/meminfo").unwrap();
    let reader = BufReader::new(f);

    for line in reader.lines() {
        let s: String = line.unwrap();
        let cap = regex.captures(s.as_str()).unwrap();
        let s = cap[1].replace('(', "_").replace(')', "");
        map.insert(s.to_lowercase(), cap[2].to_string());
    }

    map
}
