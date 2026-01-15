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
