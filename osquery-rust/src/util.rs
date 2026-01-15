use thrift::{ApplicationError, ApplicationErrorKind};

pub trait OptionToThriftResult<T> {
    fn ok_or_thrift_err<F>(self, err_fn: F) -> thrift::Result<T>
    where
        F: FnOnce() -> String;
}

impl<T> OptionToThriftResult<T> for Option<T> {
    fn ok_or_thrift_err<F>(self, err_fn: F) -> thrift::Result<T>
    where
        F: FnOnce() -> String,
    {
        self.ok_or_else(|| {
            thrift::Error::Application(ApplicationError::new(
                ApplicationErrorKind::InternalError,
                err_fn(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_some_returns_ok() {
        let opt: Option<i32> = Some(42);
        let result = opt.ok_or_thrift_err(|| "error".to_string());

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_none_returns_thrift_error() {
        let opt: Option<i32> = None;
        let result = opt.ok_or_thrift_err(|| "custom error message".to_string());

        assert!(result.is_err());
        let err = result.unwrap_err();

        // Verify it's an Application error with InternalError kind
        match err {
            thrift::Error::Application(app_err) => {
                assert_eq!(app_err.kind, ApplicationErrorKind::InternalError);
                assert!(app_err.message.contains("custom error message"));
            }
            _ => panic!("Expected Application error"),
        }
    }

    #[test]
    fn test_error_message_is_lazy() {
        // Verify the error function is only called when Option is None
        let mut called = false;

        let opt: Option<i32> = Some(1);
        let _ = opt.ok_or_thrift_err(|| {
            called = true;
            "error".to_string()
        });

        assert!(!called, "Error function should not be called for Some");
    }

    #[test]
    fn test_works_with_different_types() {
        // Test with String
        let opt_str: Option<String> = Some("hello".to_string());
        let result = opt_str.ok_or_thrift_err(|| "error".to_string());
        assert_eq!(result.unwrap(), "hello");

        // Test with Vec
        let opt_vec: Option<Vec<u8>> = Some(vec![1, 2, 3]);
        let result = opt_vec.ok_or_thrift_err(|| "error".to_string());
        assert_eq!(result.unwrap(), vec![1, 2, 3]);
    }
}
