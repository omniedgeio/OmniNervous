#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use omni_common::{SessionEntry, FdbEntry};

#[map]
static mut SESSIONS: HashMap<u32, SessionEntry> = HashMap::with_max_entries(1024, 0);

#[map]
static mut FDB: HashMap<[u8; 6], FdbEntry> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_synapse(ctx: XdpContext) -> u32 {
    match try_xdp_synapse(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_synapse(_ctx: XdpContext) -> Result<u32, ()> {
    // info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
