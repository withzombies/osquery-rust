/// TablePlugin enum and core implementations
use crate::_osquery::{
    ExtensionPluginRequest, ExtensionPluginResponse, ExtensionResponse, ExtensionStatus,
};
use crate::plugin::table::traits::{ReadOnlyTable, Table};
use crate::plugin::{OsqueryPlugin, Registry};
use enum_dispatch::enum_dispatch;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
#[enum_dispatch(OsqueryPlugin)]
pub enum TablePlugin {
    Writeable(Arc<Mutex<dyn Table>>),
    Readonly(Arc<dyn ReadOnlyTable>),
}

impl TablePlugin {
    pub fn from_writeable_table<R: Table>(table: R) -> Self {
        TablePlugin::Writeable(Arc::new(Mutex::new(table)))
    }

    pub fn from_readonly_table<R: ReadOnlyTable>(table: R) -> Self {
        TablePlugin::Readonly(Arc::new(table))
    }
}

impl OsqueryPlugin for TablePlugin {
    fn name(&self) -> String {
        match self {
            TablePlugin::Writeable(table) => {
                let Ok(table) = table.lock() else {
                    return "unable-to-get-table-name".to_string();
                };

                table.name()
            }
            TablePlugin::Readonly(table) => table.name(),
        }
    }

    fn registry(&self) -> Registry {
        Registry::Table
    }

    fn routes(&self) -> ExtensionPluginResponse {
        let mut resp = ExtensionPluginResponse::new();

        let columns = match self {
            TablePlugin::Writeable(table) => {
                let Ok(table) = table.lock() else {
                    log::error!("Plugin was unavailable, could not lock table");
                    return resp;
                };

                table.columns()
            }
            TablePlugin::Readonly(table) => table.columns(),
        };

        for column in &columns {
            let mut r: BTreeMap<String, String> = BTreeMap::new();

            r.insert("id".to_string(), "column".to_string());
            r.insert("name".to_string(), column.name());
            r.insert("type".to_string(), column.t());
            r.insert("op".to_string(), column.o());

            resp.push(r);
        }

        resp
    }

    fn ping(&self) -> ExtensionStatus {
        ExtensionStatus::new(0, None, None)
    }

    fn handle_call(&self, request: ExtensionPluginRequest) -> ExtensionResponse {
        self.parse_request(request)
    }

    fn shutdown(&self) {
        match self {
            TablePlugin::Writeable(table) => {
                if let Ok(table) = table.lock() {
                    table.shutdown();
                }
            }
            TablePlugin::Readonly(table) => table.shutdown(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::table::column_def::{ColumnDef, ColumnOptions, ColumnType};

    struct TestReadOnlyTable;

    impl ReadOnlyTable for TestReadOnlyTable {
        fn name(&self) -> String {
            "test_readonly_table".to_string()
        }

        fn columns(&self) -> Vec<ColumnDef> {
            vec![ColumnDef::new(
                "test_column",
                ColumnType::Text,
                ColumnOptions::empty(),
            )]
        }

        fn generate(&self, _request: ExtensionPluginRequest) -> ExtensionResponse {
            ExtensionResponse::new(ExtensionStatus::new(0, None, None), vec![])
        }

        fn shutdown(&self) {}
    }

    #[test]
    fn test_readonly_table_plugin_name() {
        let plugin = TablePlugin::from_readonly_table(TestReadOnlyTable);
        assert_eq!(plugin.name(), "test_readonly_table");
    }

    #[test]
    fn test_readonly_table_registry() {
        let plugin = TablePlugin::from_readonly_table(TestReadOnlyTable);
        assert_eq!(plugin.registry(), Registry::Table);
    }

    #[test]
    fn test_readonly_table_plugin_columns() {
        let plugin = TablePlugin::from_readonly_table(TestReadOnlyTable);
        let routes = plugin.routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].get("name").unwrap(), "test_column");
    }

    #[test]
    fn test_ping_returns_default_status() {
        let plugin = TablePlugin::from_readonly_table(TestReadOnlyTable);
        let status = plugin.ping();
        assert_eq!(status.code, Some(0));
    }
}
