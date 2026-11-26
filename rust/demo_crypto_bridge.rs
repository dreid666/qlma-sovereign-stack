//! DEMONSTRATION ONLY: fixed data, not ML-DSA-65 or real cryptography.

use std::ptr;
use std::sync::OnceLock;

pub struct DemoKeyPair {
    pub public_key: [u8; 1952],
}

impl DemoKeyPair {
    fn generate() -> Self {
        Self { public_key: [42; 1952] }
    }
}

static DEMO_KEY: OnceLock<DemoKeyPair> = OnceLock::new();

#[no_mangle]
pub extern "C" fn demo_export_public_key(out_buffer: *mut u8, max_len: usize) -> isize {
    if out_buffer.is_null() {
        return -1;
    }
    let keypair = DEMO_KEY.get_or_init(DemoKeyPair::generate);
    let public_key = &keypair.public_key;
    if max_len < public_key.len() {
        return -2;
    }
    unsafe {
        ptr::copy_nonoverlapping(public_key.as_ptr(), out_buffer, public_key.len());
    }
    public_key.len() as isize
}
