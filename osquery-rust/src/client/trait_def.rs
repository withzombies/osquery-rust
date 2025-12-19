/// Trait definitions for osquery client communication
use crate::_osquery as osquery;

/// Trait for osquery daemon communication - enables mocking in tests.
///
/// This trait exposes only the methods that `Server` actually needs to communicate
/// with the osquery daemon. Implementing this trait allows creating mock clients
/// for testing without requiring a real osquery socket connection.
#[cfg_attr(test, mockall::automock)]
pub trait OsqueryClient: Send {
    /// Register this extension with the osquery daemon.
    fn register_extension(
        &mut self,
        info: osquery::InternalExtensionInfo,
        registry: osquery::ExtensionRegistry,
    ) -> thrift::Result<osquery::ExtensionStatus>;

    /// Deregister this extension from the osquery daemon.
    fn deregister_extension(
        &mut self,
        uuid: osquery::ExtensionRouteUUID,
    ) -> thrift::Result<osquery::ExtensionStatus>;

    /// Ping the osquery daemon to maintain the connection.
    fn ping(&mut self) -> thrift::Result<osquery::ExtensionStatus>;

    /// Execute a SQL query against osquery.
    fn query(&mut self, sql: String) -> thrift::Result<crate::ExtensionResponse>;

    /// Get column information for a SQL query without executing it.
    fn get_query_columns(&mut self, sql: String) -> thrift::Result<crate::ExtensionResponse>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::_osquery::*;

    #[test]
    fn test_osquery_client_trait_methods() {
        let mut mock_client = MockOsqueryClient::new();
        
        let test_info = InternalExtensionInfo {
            name: Some("test_extension".to_string()),
            version: Some("1.0.0".to_string()),
            sdk_version: Some("5.0.0".to_string()),
            min_sdk_version: Some("5.0.0".to_string()),
        };
        
        let test_registry = ExtensionRegistry::new();
        let test_status = ExtensionStatus { 
            code: Some(0), 
            message: Some("OK".to_string()), 
            uuid: Some(123) 
        };
        let test_response = ExtensionResponse { 
            status: Some(test_status.clone()), 
            response: Some(Vec::new()) 
        };
        
        mock_client.expect_register_extension()
            .times(1)
            .returning(move |_, _| Ok(test_status.clone()));
        
        mock_client.expect_deregister_extension()
            .times(1)
            .returning(move |_| Ok(ExtensionStatus { 
                code: Some(0), 
                message: Some("OK".to_string()), 
                uuid: Some(123) 
            }));
        
        mock_client.expect_ping()
            .times(1)
            .returning(|| Ok(ExtensionStatus { 
                code: Some(0), 
                message: Some("OK".to_string()), 
                uuid: Some(123) 
            }));
        
        mock_client.expect_query()
            .times(1)
            .returning(move |_| Ok(test_response.clone()));
        
        mock_client.expect_get_query_columns()
            .times(1)
            .returning(move |_| Ok(ExtensionResponse { 
                status: Some(ExtensionStatus { 
                    code: Some(0), 
                    message: Some("OK".to_string()), 
                    uuid: Some(123) 
                }), 
                response: Some(Vec::new()) 
            }));
        
        let result = mock_client.register_extension(test_info, test_registry);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().code, Some(0));
        
        let result = mock_client.deregister_extension(123);
        assert!(result.is_ok());
        
        let result = mock_client.ping();
        assert!(result.is_ok());
        
        let result = mock_client.query("SELECT 1".to_string());
        assert!(result.is_ok());
        
        let result = mock_client.get_query_columns("SELECT 1".to_string());
        assert!(result.is_ok());
    }
}