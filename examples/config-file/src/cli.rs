use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    name = "config-file",
    long_about = "A config plugin that reads configuration from JSON files"
)]
#[command(arg_required_else_help = true)]
pub struct Args {
    /// Path to the osquery socket.
    #[arg(long, value_name = "PATH_TO_SOCKET")]
    pub socket: String,

    /// Path to the configuration file.
    #[arg(
        short = 'c',
        long = "config",
        default_value = "/etc/osquery/osquery.conf"
    )]
    pub config_file: String,

    /// Path to the packs directory.
    #[arg(short = 'p', long = "packs", default_value = "/etc/osquery/packs")]
    pub packs_dir: String,

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
