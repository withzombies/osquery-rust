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
    pub standalone: bool,

    // Operating in socket mode
    #[clap(long, value_name = "PATH_TO_SOCKET")]
    pub socket: Option<String>,

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
    pub fn standalone(&self) -> bool {
        self.standalone
    }

    pub fn socket(&self) -> Option<String> {
        self.socket.clone()
    }
}
