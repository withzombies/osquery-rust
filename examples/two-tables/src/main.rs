mod cli;
mod t1;
mod t2;

use crate::cli::Args;
use crate::t1::Table1;
use crate::t2::Table2;
use clap::{Parser, crate_name};
use osquery_rust::Server;
use osquery_rust::plugin::Plugin;
use std::io::{Error, ErrorKind};

fn main() -> std::io::Result<()> {
    env_logger::init();

    let args = Args::parse();

    if !args.standalone() {
        let Some(socket) = args.socket() else {
            return Err(Error::new(ErrorKind::InvalidInput, "No socket provided"));
        };

        let mut manager = Server::new(Some(crate_name!()), socket.as_str())?;

        manager.register_plugin(Plugin::readonly_table(Table1::new()));
        manager.register_plugin(Plugin::table(Table2::new()));

        manager.run().map_err(Error::other)?;
    } else {
        todo!("standalone mode has not been implemented");
    }

    Ok(())
}
