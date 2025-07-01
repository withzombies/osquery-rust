#[derive(clap::Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(arg_required_else_help = true)]
pub struct Args {
    /// Path to the osquery socket
    #[clap(long, value_name = "PATH_TO_SOCKET")]
    pub socket: String,

    /// Syslog facility to use
    #[clap(short, long, default_value = "daemon")]
    pub facility: String,

    /// Syslog server address (for remote syslog)
    #[clap(long)]
    pub remote: Option<String>,

    /// Delay in seconds between connectivity checks.
    #[clap(long, default_value_t = 30)]
    pub interval: u32,

    /// Time in seconds to wait for autoloaded extensions until connection times out.
    #[clap(long, default_value_t = 30)]
    pub timeout: u32,

    /// Enable verbose informational messages.
    #[clap(long)]
    pub verbose: bool,
}

impl Args {
    pub fn socket(&self) -> &str {
        &self.socket
    }

    pub fn facility(&self) -> &str {
        &self.facility
    }

    pub fn remote(&self) -> Option<&str> {
        self.remote.as_deref()
    }
}
