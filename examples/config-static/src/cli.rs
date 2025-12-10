use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    name = "config-static",
    long_about = "A config plugin that provides a static configuration enabling file events monitoring on /tmp"
)]
pub struct Args {
    /// Path to the osquery socket (can also be set via OSQUERY_SOCKET env var).
    #[arg(
        long,
        env = "OSQUERY_SOCKET",
        default_value = "/var/osquery/osquery.em"
    )]
    pub socket: String,

    /// Delay in seconds between connectivity checks.
    #[arg(long, default_value_t = 30)]
    pub interval: u32,

    /// Time in seconds to wait for autoloaded extensions until connection times out.
    #[arg(long, default_value_t = 30)]
    pub timeout: u32,

    /// Enable verbose informational messages.
    #[arg(long)]
    pub verbose: bool,
}
