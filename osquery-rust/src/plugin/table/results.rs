/// Result types for table operations
use std::fmt;

/// Result of an insert operation
#[derive(Debug, PartialEq, Eq)]
pub enum InsertResult {
    Ok(String), // Returns the ID of the inserted row
    Error(String),
}

/// Result of an update operation
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateResult {
    Ok,
    NotFound,
    Error(String),
}

/// Result of a delete operation
#[derive(Debug, PartialEq, Eq)]
pub enum DeleteResult {
    Ok,
    NotFound,
    Error(String),
}

impl fmt::Display for InsertResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InsertResult::Ok(id) => write!(f, "Insert successful: {}", id),
            InsertResult::Error(msg) => write!(f, "Insert error: {}", msg),
        }
    }
}

impl fmt::Display for UpdateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateResult::Ok => write!(f, "Update successful"),
            UpdateResult::NotFound => write!(f, "Update failed: not found"),
            UpdateResult::Error(msg) => write!(f, "Update error: {}", msg),
        }
    }
}

impl fmt::Display for DeleteResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeleteResult::Ok => write!(f, "Delete successful"),
            DeleteResult::NotFound => write!(f, "Delete failed: not found"),
            DeleteResult::Error(msg) => write!(f, "Delete error: {}", msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_result_display() {
        assert_eq!(
            InsertResult::Ok("123".to_string()).to_string(),
            "Insert successful: 123"
        );
        assert_eq!(
            InsertResult::Error("invalid data".to_string()).to_string(),
            "Insert error: invalid data"
        );
    }

    #[test]
    fn test_update_result_display() {
        assert_eq!(UpdateResult::Ok.to_string(), "Update successful");
        assert_eq!(
            UpdateResult::NotFound.to_string(),
            "Update failed: not found"
        );
        assert_eq!(
            UpdateResult::Error("constraint violation".to_string()).to_string(),
            "Update error: constraint violation"
        );
    }

    #[test]
    fn test_delete_result_display() {
        assert_eq!(DeleteResult::Ok.to_string(), "Delete successful");
        assert_eq!(
            DeleteResult::NotFound.to_string(),
            "Delete failed: not found"
        );
        assert_eq!(
            DeleteResult::Error("foreign key constraint".to_string()).to_string(),
            "Delete error: foreign key constraint"
        );
    }

    #[test]
    fn test_result_equality() {
        assert_eq!(
            InsertResult::Ok("1".to_string()),
            InsertResult::Ok("1".to_string())
        );
        assert_ne!(
            InsertResult::Ok("1".to_string()),
            InsertResult::Ok("2".to_string())
        );

        assert_eq!(UpdateResult::Ok, UpdateResult::Ok);
        assert_ne!(UpdateResult::Ok, UpdateResult::NotFound);

        assert_eq!(DeleteResult::Ok, DeleteResult::Ok);
        assert_ne!(DeleteResult::Ok, DeleteResult::NotFound);
    }
}
