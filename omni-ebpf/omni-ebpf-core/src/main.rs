#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use omni_common::{SessionEntry, FdbEntry, PacketHeader};

// Session map keyed by session_id
#[map]
static mut SESSIONS: HashMap<u32, SessionEntry> = HashMap::with_max_entries(1024, 0);

// FDB map keyed by MAC address
#[map]
static mut FDB: HashMap<[u8; 6], FdbEntry> = HashMap::with_max_entries(1024, 0);

// Constants for parsing
const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const OMNI_HDR_LEN: usize = 12; // session_id (4) + nonce (8)
const ETH_P_IPV4: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
const OMNI_PORT: u16 = 51820;

#[xdp]
pub fn xdp_synapse(ctx: XdpContext) -> u32 {
    match try_xdp_synapse(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_synapse(ctx: XdpContext) -> Result<u32, ()> {
    // Parse Ethernet header
    let eth_proto: *const u16 = ptr_at(&ctx, 12)?;
    let eth_proto = u16::from_be(unsafe { *eth_proto });

    // Only process IPv4
    if eth_proto != ETH_P_IPV4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse IP header
    let ip_proto: *const u8 = ptr_at(&ctx, ETH_HDR_LEN + 9)?;
    let ip_proto = unsafe { *ip_proto };

    // Only process UDP
    if ip_proto != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse UDP header - destination port
    let dst_port: *const u16 = ptr_at(&ctx, ETH_HDR_LEN + IPV4_HDR_LEN + 2)?;
    let dst_port = u16::from_be(unsafe { *dst_port });

    // Only process OmniNervous port
    if dst_port != OMNI_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse OmniNervous header
    let omni_offset = ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN;
    let session_id: *const u32 = ptr_at(&ctx, omni_offset)?;
    let session_id = u32::from_be(unsafe { *session_id });

    // Lookup session in map
    let session = unsafe { SESSIONS.get(&session_id) };

    match session {
        Some(_entry) => {
            // Session found - packet is authorized
            // TODO: Decrypt payload using entry.key
            info!(&ctx, "OmniNervous: session {} authorized", session_id);
            Ok(xdp_action::XDP_PASS)
        }
        None => {
            // Unknown session - drop silently (Cryptographic Silence)
            Ok(xdp_action::XDP_DROP)
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
