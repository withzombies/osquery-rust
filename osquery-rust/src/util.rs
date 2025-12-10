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
}
