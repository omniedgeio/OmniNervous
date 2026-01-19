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
    // Update packet counter
    let stats = unsafe { PACKET_STATS.get_ptr_mut(0) };
    if let Some(counter) = stats {
        unsafe { *counter += 1 };
    }

    // For Phase 7.2: Maximize XDP_REDIRECT usage
    // Classify packets and route known flows via kernel fast path

    // Quick Ethernet header check
    if ctx.data_end() - ctx.data() < 14 {
        return Ok(xdp_action::XDP_PASS); // Too short, let userspace handle
    }

    // For now, pass to userspace for full processing
    // TODO: Implement session-based routing for XDP_REDIRECT maximization
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}