use alloc::vec::Vec;

/// One recorded value. Scalars are never JSON.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    F32(f32),
    F64(f64),
    I64(i64),
    Bool(bool),
    Enum(u32),
    /// Degrees multiplied by 1e7.
    Position {
        lat_e7: i32,
        lon_e7: i32,
    },
    /// Size-capped opaque bytes, for values with no scalar form.
    Blob(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ValueType {
    F32 = 1,
    F64 = 2,
    I64 = 3,
    Bool = 4,
    Enum = 5,
    Position = 6,
    Blob = 7,
}

impl Value {
    pub fn value_type(&self) -> ValueType {
        match self {
            Value::F32(_) => ValueType::F32,
            Value::F64(_) => ValueType::F64,
            Value::I64(_) => ValueType::I64,
            Value::Bool(_) => ValueType::Bool,
            Value::Enum(_) => ValueType::Enum,
            Value::Position { .. } => ValueType::Position,
            Value::Blob(_) => ValueType::Blob,
        }
    }
}

impl ValueType {
    pub fn from_u8(v: u8) -> Option<ValueType> {
        match v {
            1 => Some(ValueType::F32),
            2 => Some(ValueType::F64),
            3 => Some(ValueType::I64),
            4 => Some(ValueType::Bool),
            5 => Some(ValueType::Enum),
            6 => Some(ValueType::Position),
            7 => Some(ValueType::Blob),
            _ => None,
        }
    }
}
