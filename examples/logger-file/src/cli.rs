#[derive(clap::Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(arg_required_else_help = true)]
pub struct Args {
    /// Path to the osquery socket
    #[clap(long, value_name = "PATH_TO_SOCKET")]
    pub socket: String,

    /// Path to the log file (can also be set via FILE_LOGGER_PATH env var)
    #[clap(
        short,
        long,
        env = "FILE_LOGGER_PATH",
        default_value = "/tmp/osquery-logger.log"
    )]
    pub log_file: std::path::PathBuf,

    /// Delay in seconds between connectivity checks.
    #[clap(long, default_value_t = 30)]
    pub interval: u32,

    /// Time in seconds to wait for autoloaded extensions until connection times out.
    #[clap(long, default_value_t = 30)]
    pub timeout: u32,

    /// Enable verbose informational messages.
    #[clap(long, default_value = "true")]
    pub verbose: bool,
}

impl Args {
    pub fn socket(&self) -> &str {
        &self.socket
    }

    pub fn log_file(&self) -> &std::path::Path {
        &self.log_file
    }
}
