use crate::plugin::table::ColumnType;
use std::collections::HashMap;

// QueryConstraints contains the constraints from the WHERE clause of the query,
// that can optionally be used to optimize the table generation. Note that the
// _osquery SQLite engine will perform the filtering with these constraints, so
// it is not mandatory that they be used in table generation.
// QueryConstraints is a map from column name to the details of the
// constraints on that column.
pub type QueryConstraints = HashMap<String, ConstraintList>;

// ConstraintList contains the details of the constraints for the given column.
#[allow(dead_code)]
pub struct ConstraintList {
    affinity: ColumnType,
    constraints: Vec<Constraint>,
}

impl ConstraintList {
    /// Create a new ConstraintList with the given column type
    #[allow(dead_code)]
    pub fn new(affinity: ColumnType) -> Self {
        Self {
            affinity,
            constraints: Vec::new(),
        }
    }

    /// Add a constraint to this list
    #[allow(dead_code)]
    pub fn add_constraint(&mut self, op: Operator, expr: String) {
        self.constraints.push(Constraint { op, expr });
    }

    /// Get the column type affinity
    #[allow(dead_code)]
    pub fn affinity(&self) -> &ColumnType {
        &self.affinity
    }

    /// Get the number of constraints
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.constraints.len()
    }

    /// Check if there are no constraints
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }
}

// Constraint contains both an operator and an expression that are applied as
// constraints in the query.
#[allow(dead_code)]
struct Constraint {
    op: Operator,
    expr: String,
}

/// Operators for query constraints, mapping to osquery's constraint operators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Operator {
    /// Unique constraint (code 1)
    Unique = 1,
    /// Equality constraint (code 2)
    Equals = 2,
    /// Greater than constraint (code 4)
    GreaterThan = 4,
    /// Less than or equals constraint (code 8)
    LessThanOrEquals = 8,
    /// Less than constraint (code 16)
    LessThan = 16,
    /// Greater than or equals constraint (code 32)
    GreaterThanOrEquals = 32,
    /// Match constraint (code 64)
    Match = 64,
    /// Like constraint (code 65)
    Like = 65,
    /// Glob constraint (code 66)
    Glob = 66,
    /// Regexp constraint (code 67)
    Regexp = 67,
}

impl TryFrom<i32> for Operator {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Operator::Unique),
            2 => Ok(Operator::Equals),
            4 => Ok(Operator::GreaterThan),
            8 => Ok(Operator::LessThanOrEquals),
            16 => Ok(Operator::LessThan),
            32 => Ok(Operator::GreaterThanOrEquals),
            64 => Ok(Operator::Match),
            65 => Ok(Operator::Like),
            66 => Ok(Operator::Glob),
            67 => Ok(Operator::Regexp),
            _ => Err(format!("Unknown operator code: {value}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_list_creation() {
        let list = ConstraintList::new(ColumnType::Text);
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert!(matches!(list.affinity(), ColumnType::Text));
    }

    #[test]
    fn test_constraint_list_with_constraints() {
        let mut list = ConstraintList::new(ColumnType::Integer);
        list.add_constraint(Operator::Equals, "42".to_string());
        list.add_constraint(Operator::GreaterThan, "10".to_string());

        assert!(!list.is_empty());
        assert_eq!(list.len(), 2);
        assert!(matches!(list.affinity(), ColumnType::Integer));
    }

    #[test]
    fn test_operator_equality_variants() {
        assert_eq!(Operator::Equals, Operator::Equals);
        assert_ne!(Operator::Equals, Operator::GreaterThan);
    }

    #[test]
    fn test_operator_comparison_variants() {
        // Test all comparison operators exist and have correct values
        assert_eq!(Operator::GreaterThan as i32, 4);
        assert_eq!(Operator::LessThan as i32, 16);
        assert_eq!(Operator::GreaterThanOrEquals as i32, 32);
        assert_eq!(Operator::LessThanOrEquals as i32, 8);
    }

    #[test]
    fn test_operator_pattern_variants() {
        // Test pattern matching operators
        assert_eq!(Operator::Match as i32, 64);
        assert_eq!(Operator::Like as i32, 65);
        assert_eq!(Operator::Glob as i32, 66);
        assert_eq!(Operator::Regexp as i32, 67);
    }

    #[test]
    fn test_operator_try_from_valid() {
        assert_eq!(Operator::try_from(1), Ok(Operator::Unique));
        assert_eq!(Operator::try_from(2), Ok(Operator::Equals));
        assert_eq!(Operator::try_from(4), Ok(Operator::GreaterThan));
        assert_eq!(Operator::try_from(8), Ok(Operator::LessThanOrEquals));
        assert_eq!(Operator::try_from(16), Ok(Operator::LessThan));
        assert_eq!(Operator::try_from(32), Ok(Operator::GreaterThanOrEquals));
        assert_eq!(Operator::try_from(64), Ok(Operator::Match));
        assert_eq!(Operator::try_from(65), Ok(Operator::Like));
        assert_eq!(Operator::try_from(66), Ok(Operator::Glob));
        assert_eq!(Operator::try_from(67), Ok(Operator::Regexp));
    }

    #[test]
    fn test_operator_try_from_invalid() {
        assert!(Operator::try_from(0).is_err());
        assert!(Operator::try_from(3).is_err());
        assert!(Operator::try_from(100).is_err());
        assert!(Operator::try_from(-1).is_err());
    }

    #[test]
    fn test_query_constraints_map() {
        let mut constraints: QueryConstraints = HashMap::new();

        let mut name_constraints = ConstraintList::new(ColumnType::Text);
        name_constraints.add_constraint(Operator::Equals, "test".to_string());

        let mut age_constraints = ConstraintList::new(ColumnType::Integer);
        age_constraints.add_constraint(Operator::GreaterThan, "18".to_string());
        age_constraints.add_constraint(Operator::LessThan, "65".to_string());

        constraints.insert("name".to_string(), name_constraints);
        constraints.insert("age".to_string(), age_constraints);

        assert_eq!(constraints.len(), 2);
        assert!(constraints.contains_key("name"));
        assert!(constraints.contains_key("age"));

        let name_list = constraints.get("name");
        assert!(name_list.is_some());
        assert_eq!(name_list.map(|l| l.len()).unwrap_or(0), 1);

        let age_list = constraints.get("age");
        assert!(age_list.is_some());
        assert_eq!(age_list.map(|l| l.len()).unwrap_or(0), 2);
    }

    #[test]
    fn test_constraint_list_different_column_types() {
        let text_list = ConstraintList::new(ColumnType::Text);
        let int_list = ConstraintList::new(ColumnType::Integer);
        let bigint_list = ConstraintList::new(ColumnType::BigInt);
        let double_list = ConstraintList::new(ColumnType::Double);

        assert!(matches!(text_list.affinity(), ColumnType::Text));
        assert!(matches!(int_list.affinity(), ColumnType::Integer));
        assert!(matches!(bigint_list.affinity(), ColumnType::BigInt));
        assert!(matches!(double_list.affinity(), ColumnType::Double));
    }
}
