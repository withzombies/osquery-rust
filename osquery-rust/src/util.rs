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
    fn test_ok_or_thrift_err_with_some() {
        let value: Option<i32> = Some(42);
        let result = value.ok_or_thrift_err(|| "should not be called".to_string());
        assert!(result.is_ok());
        assert_eq!(result.ok(), Some(42));
    }

    #[test]
    fn test_ok_or_thrift_err_with_none() {
        let value: Option<i32> = None;
        let result = value.ok_or_thrift_err(|| "custom error message".to_string());
        assert!(result.is_err());

        // Verify it's an Application error with InternalError kind
        let err = result.err();
        assert!(err.is_some(), "Expected error");
        assert!(
            matches!(
                &err,
                Some(thrift::Error::Application(app_err))
                    if app_err.kind == ApplicationErrorKind::InternalError
                    && app_err.message == "custom error message"
            ),
            "Expected Application error with InternalError kind"
        );
    }

    #[test]
    fn test_ok_or_thrift_err_different_types() {
        let value: Option<String> = Some("test".to_string());
        let result = value.ok_or_thrift_err(|| "error".to_string());
        assert!(result.is_ok());
        assert_eq!(result.ok(), Some("test".to_string()));

        let value: Option<Vec<i32>> = None;
        let result = value.ok_or_thrift_err(|| "vector error".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_ok_or_thrift_err_closure_evaluation() {
        let mut called = false;
        let value: Option<i32> = None;

        let _result = value.ok_or_thrift_err(|| {
            called = true;
            "closure called".to_string()
        });

        assert!(called, "Error function should be called for None");
    }

    #[test]
    fn test_ok_or_thrift_err_closure_not_evaluated() {
        let mut called = false;
        let value: Option<i32> = Some(42);

        let result = value.ok_or_thrift_err(|| {
            called = true;
            "should not be called".to_string()
        });

        assert!(!called, "Error function should not be called for Some");
        assert!(result.is_ok());
    }

    #[test]
    fn test_ok_or_thrift_err_empty_error_message() {
        let value: Option<i32> = None;
        let result = value.ok_or_thrift_err(|| "".to_string());
        assert!(result.is_err());

        let err = result.err().unwrap();
        if let thrift::Error::Application(app_err) = err {
            assert_eq!(app_err.message, "");
        } else {
            panic!("Expected Application error");
        }
    }
}
