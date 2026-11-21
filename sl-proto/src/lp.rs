//! The message every signature in the protocol is taken over: a context naming what is
//! signed, then each field after its length, so no byte can move between two fields and no
//! signature over one kind of message is valid for another.
use alloc::vec::Vec;

pub fn signed_message(context: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let len = context.len() + fields.iter().map(|f| f.len() + 4).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(context);
    for field in fields {
        out.extend_from_slice(&(field.len() as u32).to_le_bytes());
        out.extend_from_slice(field);
    }
    out
}
