#![no_main]

use libfuzzer_sys::fuzz_target;
use chilli_net::dhcp::DhcpPacket;

fuzz_target!(|data: &[u8]| {
    // Call the function we want to fuzz.
    // The result is ignored; we are only interested in whether the call panics.
    let _ = DhcpPacket::from_bytes(data);
});
