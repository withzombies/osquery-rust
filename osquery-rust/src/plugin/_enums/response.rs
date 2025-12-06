use crate::ExtensionResponse;
use crate::_osquery::ExtensionStatus;
use std::collections::BTreeMap;

pub enum ExtensionResponseEnum {
    Success(),
    SuccessWithId(u64),
    SuccessWithCode(i32),
    Failure(String),
    Constraint(),
    Readonly(),
}

impl From<ExtensionResponseEnum> for ExtensionResponse {
    fn from(value: ExtensionResponseEnum) -> Self {
        let mut resp = BTreeMap::<String, String>::new();

        let code = match value {
            ExtensionResponseEnum::Success() => {
                resp.insert("status".to_string(), "success".to_string());
                0
            }
            ExtensionResponseEnum::SuccessWithId(id) => {
                resp.insert("status".to_string(), "success".to_string());
                resp.insert("id".to_string(), id.to_string());
                0
            }
            ExtensionResponseEnum::SuccessWithCode(code) => {
                resp.insert("status".to_string(), "success".to_string());
                code
            }
            ExtensionResponseEnum::Failure(msg) => {
                resp.insert("status".to_string(), "failure".to_string());
                resp.insert("message".to_string(), msg.to_string());
                1
            }
            ExtensionResponseEnum::Constraint() => {
                resp.insert("status".to_string(), "constraint".to_string());
                1
            }
            ExtensionResponseEnum::Readonly() => {
                resp.insert("status".to_string(), "readonly".to_string());
                1
            }
        };

        ExtensionResponse::new(ExtensionStatus::new(code, None, None), vec![resp])
    }
}
