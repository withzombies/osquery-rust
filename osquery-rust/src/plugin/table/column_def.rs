use bitflags::bitflags;
use strum_macros::Display;

// ColumnDef defines a column used in a table plugin.
// Prefer using the helper functions to create a ColumnDef.
#[derive(Clone, Debug)]
pub struct ColumnDef {
    name: String,
    t: ColumnType,
    o: ColumnOptions,
}

#[derive(Clone, Display, Debug)]
#[strum(serialize_all = "UPPERCASE")]
pub enum ColumnType {
    // TEXT: containing strings
    Text,
    // INTEGER: containing integers
    Integer,
    // BIGINT: containing large integers
    BigInt,
    // DOUBLE: containing floating point values
    Double,
}

bitflags! {
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct ColumnOptions: u32 {
        const DEFAULT = 0;
        const INDEX = 1;
        const REQUIRED = 2;
        const ADDITIONAL = 4;
        const OPTIMIZED = 8;
        const HIDDEN = 16;
        const COLLATEBINARY = 32;
    }
}

impl ColumnDef {
    pub fn new(name: &str, t: ColumnType, o: ColumnOptions) -> Self {
        ColumnDef {
            name: name.to_owned(),
            t,
            o,
        }
    }

    pub(crate) fn name(&self) -> String {
        self.name.to_string()
    }

    pub(crate) fn t(&self) -> String {
        self.t.to_string()
    }

    pub(crate) fn o(&self) -> String {
        self.o.bits().to_string()
    }
}
