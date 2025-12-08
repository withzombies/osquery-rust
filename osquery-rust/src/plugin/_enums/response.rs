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

#[cfg(test)]
mod tests {
    use super::*;

    fn get_first_row(resp: &ExtensionResponse) -> Option<&BTreeMap<String, String>> {
        resp.response.as_ref().and_then(|r| r.first())
    }

    #[test]
    fn test_success_response() {
        let resp: ExtensionResponse = ExtensionResponseEnum::Success().into();

        // Check status code 0
        let status = resp.status.as_ref();
        assert!(status.is_some());
        assert_eq!(status.and_then(|s| s.code), Some(0));

        // Check response contains "status": "success"
        let row = get_first_row(&resp);
        assert!(row.is_some());
        assert_eq!(
            row.and_then(|r| r.get("status")).map(|s| s.as_str()),
            Some("success")
        );
    }

    #[test]
    fn test_success_with_id_response() {
        let resp: ExtensionResponse = ExtensionResponseEnum::SuccessWithId(42).into();

        let status = resp.status.as_ref();
        assert_eq!(status.and_then(|s| s.code), Some(0));

        let row = get_first_row(&resp);
        assert!(row.is_some());
        assert_eq!(
            row.and_then(|r| r.get("status")).map(|s| s.as_str()),
            Some("success")
        );
        assert_eq!(
            row.and_then(|r| r.get("id")).map(|s| s.as_str()),
            Some("42")
        );
    }

    #[test]
    fn test_success_with_code_response() {
        let resp: ExtensionResponse = ExtensionResponseEnum::SuccessWithCode(5).into();

        // Check status code is the custom code
        let status = resp.status.as_ref();
        assert_eq!(status.and_then(|s| s.code), Some(5));

        let row = get_first_row(&resp);
        assert!(row.is_some());
        assert_eq!(
            row.and_then(|r| r.get("status")).map(|s| s.as_str()),
            Some("success")
        );
    }

    #[test]
    fn test_failure_response() {
        let resp: ExtensionResponse =
            ExtensionResponseEnum::Failure("error msg".to_string()).into();

        let status = resp.status.as_ref();
        assert_eq!(status.and_then(|s| s.code), Some(1));

        let row = get_first_row(&resp);
        assert!(row.is_some());
        assert_eq!(
            row.and_then(|r| r.get("status")).map(|s| s.as_str()),
            Some("failure")
        );
        assert_eq!(
            row.and_then(|r| r.get("message")).map(|s| s.as_str()),
            Some("error msg")
        );
    }

    #[test]
    fn test_constraint_response() {
        let resp: ExtensionResponse = ExtensionResponseEnum::Constraint().into();

        let status = resp.status.as_ref();
        assert_eq!(status.and_then(|s| s.code), Some(1));

        let row = get_first_row(&resp);
        assert!(row.is_some());
        assert_eq!(
            row.and_then(|r| r.get("status")).map(|s| s.as_str()),
            Some("constraint")
        );
    }

    #[test]
    fn test_readonly_response() {
        let resp: ExtensionResponse = ExtensionResponseEnum::Readonly().into();

        let status = resp.status.as_ref();
        assert_eq!(status.and_then(|s| s.code), Some(1));

        let row = get_first_row(&resp);
        assert!(row.is_some());
        assert_eq!(
            row.and_then(|r| r.get("status")).map(|s| s.as_str()),
            Some("readonly")
        );
    }
}
