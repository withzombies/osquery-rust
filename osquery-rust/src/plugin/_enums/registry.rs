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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_registry_display() {
        assert_eq!(Registry::Config.to_string(), "config");
        assert_eq!(Registry::Logger.to_string(), "logger");
        assert_eq!(Registry::Table.to_string(), "table");
    }

    #[test]
    fn test_registry_from_str() {
        assert_eq!(Registry::from_str("config").unwrap(), Registry::Config);
        assert_eq!(Registry::from_str("logger").unwrap(), Registry::Logger);
        assert_eq!(Registry::from_str("table").unwrap(), Registry::Table);
    }

    #[test]
    fn test_registry_from_str_invalid() {
        let result = Registry::from_str("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_debug() {
        assert_eq!(format!("{:?}", Registry::Config), "Config");
        assert_eq!(format!("{:?}", Registry::Logger), "Logger");
        assert_eq!(format!("{:?}", Registry::Table), "Table");
    }

    #[test]
    fn test_registry_equality() {
        assert_eq!(Registry::Config, Registry::Config);
        assert_ne!(Registry::Config, Registry::Logger);
        assert_ne!(Registry::Logger, Registry::Table);
    }

    #[test]
    fn test_registry_hash() {
        use std::collections::HashMap;

        let mut map = HashMap::new();
        map.insert(Registry::Config, "config_value");
        map.insert(Registry::Logger, "logger_value");
        map.insert(Registry::Table, "table_value");

        assert_eq!(map.get(&Registry::Config), Some(&"config_value"));
        assert_eq!(map.get(&Registry::Logger), Some(&"logger_value"));
        assert_eq!(map.get(&Registry::Table), Some(&"table_value"));
    }
}
