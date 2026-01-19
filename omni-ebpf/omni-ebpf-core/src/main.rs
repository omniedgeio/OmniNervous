#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    maps::PerCpuArray,
    programs::XdpContext,
};

// Simplified stats - just packet count
#[map]
static PACKET_STATS: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

#[xdp]
pub fn xdp_synapse(ctx: XdpContext) -> u32 {
    match try_xdp_synapse(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_xdp_synapse(ctx: XdpContext) -> Result<u32, ()> {
    // Simple packet counting for testing eBPF loading
    let stats = unsafe { PACKET_STATS.get_ptr_mut(0) };
    if let Some(counter) = stats {
        unsafe { *counter += 1 };
    }

    // Pass all packets to userspace for processing
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}