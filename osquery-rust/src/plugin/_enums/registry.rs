use strum_macros::{EnumString, VariantNames};

#[derive(EnumString, VariantNames, Debug, Eq, Hash, PartialEq)]
#[strum(serialize_all = "kebab_case")]
pub enum Registry {
    Config,
    Logger,
    Table,
}

use std::fmt;

impl fmt::Display for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Registry::Config => write!(f, "config"),
            Registry::Logger => write!(f, "logger"),
            Registry::Table => write!(f, "table"),
        }
    }
}
