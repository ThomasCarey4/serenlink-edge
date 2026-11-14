/// Why a byte string could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended before the value did.
    Truncated,
    /// A number did not fit its type.
    Overflow,
    /// An enum tag or version byte was not recognised.
    BadTag(u8),
    /// A declared length or count cannot be satisfied by the input.
    BadLength,
    BadUtf8,
    /// Input continued after the value ended.
    Trailing,
    /// The encoding is known but not available in this build.
    Unsupported,
    /// A block declares more records than the caller allows.
    TooManyRecords,
}
