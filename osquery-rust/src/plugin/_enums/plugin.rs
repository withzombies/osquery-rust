use crate::_osquery as osquery;
use crate::_osquery::{ExtensionPluginRequest, ExtensionResponse};
use crate::plugin::table::{ReadOnlyTable, TablePlugin};
use crate::plugin::Table;
use crate::plugin::{OsqueryPlugin, Registry};

#[derive(Clone)]
pub enum Plugin {
    Config,
    Logger,
    Table(TablePlugin),
}

impl Plugin {
    pub fn table<T: Table + 'static>(t: T) -> Self {
        Plugin::Table(TablePlugin::from_writeable_table(t))
    }

    pub fn readonly_table<T: ReadOnlyTable + 'static>(t: T) -> Self {
        Plugin::Table(TablePlugin::from_readonly_table(t))
    }

    pub fn config() -> Self {
        Plugin::Config
    }

    pub fn logger() -> Self {
        Plugin::Logger
    }
}

impl OsqueryPlugin for Plugin {
    // Name is the name used to refer to the plugin (e.g. the name of the
    // table the plugin implements).
    fn name(&self) -> String {
        match self {
            Plugin::Config => todo!(),
            Plugin::Logger => todo!(),
            Plugin::Table(t) => t.name(),
        }
    }

    // Registry is which "registry" the plugin should be added to.
    fn registry(&self) -> Registry {
        match self {
            Plugin::Config => Registry::Config,
            Plugin::Logger => Registry::Logger,
            Plugin::Table(_) => Registry::Table,
        }
    }

    // Routes returns detailed information about the interface exposed
    // by the plugin. See the example plugins for implementation details.
    //pub(crate) fn routes(&self) -> osquery::ExtensionPluginResponse {
    fn routes(&self) -> osquery::ExtensionPluginResponse {
        match self {
            Plugin::Config => {
                todo!()
            }
            Plugin::Logger => {
                todo!()
            }
            Plugin::Table(t) => t.routes(),
        }
    }

    // Ping implements the plugin's health check. If the plugin is in a
    // healthy state, Status OK should be returned.
    fn ping(&self) -> osquery::ExtensionStatus {
        todo!()
    }

    // Call requests the plugin to perform its defined behavior, returning
    // a response containing the result.
    fn generate(&self, req: osquery::ExtensionPluginRequest) -> osquery::ExtensionResponse {
        match self {
            Plugin::Config => {
                todo!()
            }
            Plugin::Logger => {
                todo!()
            }
            Plugin::Table(t) => t.generate(req),
        }
    }

    fn update(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        match self {
            Plugin::Config => {
                todo!()
            }
            Plugin::Logger => {
                todo!()
            }
            Plugin::Table(t) => t.update(req),
        }
    }

    fn delete(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        match self {
            Plugin::Config => {
                todo!()
            }
            Plugin::Logger => {
                todo!()
            }
            Plugin::Table(t) => t.delete(req),
        }
    }

    fn insert(&self, req: ExtensionPluginRequest) -> ExtensionResponse {
        match self {
            Plugin::Config => {
                todo!()
            }
            Plugin::Logger => {
                todo!()
            }
            Plugin::Table(t) => t.insert(req),
        }
    }

    // Shutdown notifies the plugin to stop.
    fn shutdown(&self) {
        match self {
            Plugin::Config => {
                todo!()
            }
            Plugin::Logger => {
                todo!()
            }
            Plugin::Table(t) => t.shutdown(),
        }
    }
}
