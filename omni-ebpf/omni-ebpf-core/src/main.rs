#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    maps::{HashMap, Array, PerCpuArray, XskMap, CpuMap},
    programs::XdpContext,
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
};
use omni_common::{SessionEntry, SessionKey};

// Session map keyed by SessionKey (two u32s for 64-bit session ID)
#[map]
static SESSIONS: HashMap<SessionKey, SessionEntry> = HashMap::with_max_entries(1024, 0);

// FDB map keyed by MAC address (For L2 Mode)
#[map]
static FDB: HashMap<[u8; 6], SessionEntry> = HashMap::with_max_entries(1024, 0);

// Index 0: ifindex of TUN device
// Index 1: Mode (0 = L3/TUN, 1 = L2/TAP)
// Index 2: ifindex of Physical device (eth0)
#[map]
static TUN_CONFIG: Array<u32> = Array::with_max_entries(3, 0);

// Debug Stats (PerCPU)
// 0: RX_PACKETS
// 1: RX_PASS_NOT_OMNI
// 2: RX_SESSION_FOUND
// 3: RX_SESSION_MISSING
// 4: RX_DECRYPT_SUCCESS
// 5: RX_DECRYPT_FAIL
// 6: RX_REDIRECT_L3
// 7: RX_REDIRECT_L2
// 8: RX_DROP_HEAD
// 9: RX_REDIRECT_XSK
#[map]
static DEBUG_STATS: PerCpuArray<u32> = PerCpuArray::with_max_entries(11, 0);

// AF_XDP Socket Map (Phase 7.4)
#[map]
static XSK_MAP: XskMap = XskMap::with_max_entries(64, 0);

// CPU Steering Map (Phase 7.4)
#[map]
static CPU_STEER: CpuMap = CpuMap::with_max_entries(64, 0);

#[inline(always)]
fn inc_stat(_ctx: &XdpContext, idx: u32) {
    // Stat recording is best-effort
    unsafe {
        if let Some(val) = DEBUG_STATS.get_ptr_mut(idx) {
            *val += 1;
        }
    }
}

// Constants for parsing
const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20;
const IPV6_HDR_LEN: usize = 40;
const UDP_HDR_LEN: usize = 8;
const OMNI_HDR_LEN: usize = 24; // session_id (8) + sequence (8) + nonce (8)
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_UDP: u8 = 17;
const OMNI_PORT: u16 = 51820;
const POLY1305_TAG_LEN: usize = 16;
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

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[repr(C)]
struct OmniHeader {
    session_id: u64,
    sequence: u64,
    nonce: u64,
}

/// ChaCha20 quarter round operation
#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(7);
}

/// ChaCha20 block function with manual unrolling
#[inline(always)]
fn chacha20_block(key: &[u8; 32], nonce: &[u8; 8], counter: u32, output: &mut [u8; 64]) {
    let mut state = [0u32; 16];
    
    // Constants: "expand 32-byte k"
    state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
    
    // Read key using u32 chunks
    state[4] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
    state[5] = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
    state[6] = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
    state[7] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
    state[8] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
    state[9] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
    state[10] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
    state[11] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);
    
    state[12] = counter;
    state[13] = 0; // counter high
    state[14] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[15] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    
    let mut working = state;
    // Manual unrolling of 10 loops (20 rounds total)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }
    
    // Final state addition
    for i in 0..16 { 
        let val = working[i].wrapping_add(state[i]);
        let bytes = val.to_le_bytes();
        output[i * 4] = bytes[0]; 
        output[i * 4 + 1] = bytes[1]; 
        output[i * 4 + 2] = bytes[2]; 
        output[i * 4 + 3] = bytes[3];
    }
}

/// Decrypt packet in-place using ChaCha20 with u64 block XOR
#[inline(always)]
fn decrypt_payload(ctx: &XdpContext, offset: usize, len: usize, key: &[u8; 32], nonce: &[u8; 8]) -> Result<(), ()> {
    let mut counter = 1u32;
    let mut keystream = [0u8; 64];

    let mut processed = 0;
    while processed < len {
        chacha20_block(key, nonce, counter, &mut keystream);
        counter += 1;

        let block_offset = offset + processed;
        let remaining = len - processed;
        let current_block_len = if remaining > 64 { 64 } else { remaining };

        // Process in 8-byte chunks (u64)
        let mut block_idx = 0;
        while block_idx + 8 <= current_block_len {
            let p: *mut u64 = ptr_at_mut(ctx, block_offset + block_idx)?;
            // Read keystream chunk as u64
            let ks_chunk = unsafe { 
                core::ptr::read_unaligned(keystream.as_ptr().add(block_idx) as *const u64) 
            };
            unsafe { *p ^= ks_chunk };
            block_idx += 8;
        }

        // Handle terminal bytes
        while block_idx < current_block_len {
            let p: *mut u8 = ptr_at_mut(ctx, block_offset + block_idx)?;
            unsafe { *p ^= keystream[block_idx] };
            block_idx += 1;
        }

        processed += 64;
    }
    Ok(())
}

#[xdp]
pub fn xdp_synapse(ctx: XdpContext) -> u32 {
    match try_xdp_synapse(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_xdp_synapse(ctx: XdpContext) -> Result<u32, ()> {
    inc_stat(&ctx, 0); // RX_PACKETS

    let tun_idx = TUN_CONFIG.get(0).copied().unwrap_or(0);
    let _phys_idx = TUN_CONFIG.get(2).copied().unwrap_or(0);
    let current_ifindex = unsafe { (*ctx.ctx).ingress_ifindex };

    // If this is from the virtual interface (TUN), it likely lacks an Ethernet header
    if current_ifindex == tun_idx && tun_idx != 0 {
        // EGRESS: Traffic from app to VPN
        // Redirect to AF_XDP for Zero-Copy userspace encryption
        if let Ok(_) = unsafe { XSK_MAP.redirect(0, 0) } {
            inc_stat(&ctx, 9); // RX_REDIRECT_XSK
            return Ok(xdp_action::XDP_REDIRECT);
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // Normal processing for Physical Interface (ingress)
    // Parse Ethernet header
    let eth_proto_ptr: *const u16 = ptr_at(&ctx, 12)?;
    let eth_proto = u16::from_be(unsafe { *eth_proto_ptr });

    let omni_offset = if eth_proto == ETH_P_IPV4 {
        let ip_proto: *const u8 = ptr_at(&ctx, ETH_HDR_LEN + 9)?;
        if unsafe { *ip_proto } != IPPROTO_UDP { 
            inc_stat(&ctx, 1); // PASS_NOT_OMNI
            return Ok(xdp_action::XDP_PASS); 
        }
        let dst_port: *const u16 = ptr_at(&ctx, ETH_HDR_LEN + IPV4_HDR_LEN + 2)?;
        if u16::from_be(unsafe { *dst_port }) != OMNI_PORT { 
            inc_stat(&ctx, 1); // PASS_NOT_OMNI
            return Ok(xdp_action::XDP_PASS); 
        }
        ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN
    } else if eth_proto == ETH_P_IPV6 {
        let next_hdr: *const u8 = ptr_at(&ctx, ETH_HDR_LEN + 6)?;
        if unsafe { *next_hdr } != IPPROTO_UDP { 
            inc_stat(&ctx, 1); // PASS_NOT_OMNI
            return Ok(xdp_action::XDP_PASS); 
        }
        let dst_port: *const u16 = ptr_at(&ctx, ETH_HDR_LEN + IPV6_HDR_LEN + 2)?;
        if u16::from_be(unsafe { *dst_port }) != OMNI_PORT { 
            inc_stat(&ctx, 1); // PASS_NOT_OMNI
            return Ok(xdp_action::XDP_PASS); 
        }
        ETH_HDR_LEN + IPV6_HDR_LEN + UDP_HDR_LEN
    } else {
        inc_stat(&ctx, 1); // PASS_NOT_OMNI
        return Ok(xdp_action::XDP_PASS);
    };

    // Fast parse OmniNervous header
    let header: *const OmniHeader = ptr_at(&ctx, omni_offset)?;
    let session_id = unsafe { (*header).session_id };
    let nonce_bytes = unsafe { (*header).nonce.to_ne_bytes() };
    
    // Map lookup key
    let session_key = SessionKey {
        id_high: (session_id >> 32) as u32,
        id_low: (session_id & 0xFFFFFFFF) as u32,
    };

    let session = unsafe { SESSIONS.get(&session_key) };
    
    if let Some(entry) = session {
        inc_stat(&ctx, 2); // SESSION_FOUND
        
        let payload_offset = omni_offset + OMNI_HDR_LEN;
        let data_start = ctx.data();
        let data_end = ctx.data_end();
        
        if data_end <= data_start + payload_offset + POLY1305_TAG_LEN {
            inc_stat(&ctx, 5); // DECRYPT_FAIL (Too short)
            return Ok(xdp_action::XDP_DROP);
        }
        
        let total_payload_len = data_end - (data_start + payload_offset);
        let ciphertext_len = total_payload_len - POLY1305_TAG_LEN;

        // Decrypt in-place with u64 optimization
        if decrypt_payload(&ctx, payload_offset, ciphertext_len, &entry.key, &nonce_bytes).is_err() {
            inc_stat(&ctx, 5); // DECRYPT_FAIL
            return Ok(xdp_action::XDP_DROP);
        }
        inc_stat(&ctx, 4); // DECRYPT_SUCCESS

        // Get Configuration
        let tun_idx = TUN_CONFIG.get(0).copied().unwrap_or(0);
        let mode = TUN_CONFIG.get(1).copied().unwrap_or(0); // 0=L3, 1=L2

        // Strip Outer Headers
        let strip_len = payload_offset as i32;
        if unsafe { bpf_xdp_adjust_head(ctx.ctx, strip_len) } != 0 {
             inc_stat(&ctx, 8); // DROP_HEAD
             return Ok(xdp_action::XDP_DROP);
        }

        // Redirect to TUN/TAP
        if tun_idx != 0 {
            // Check if AF_XDP is enabled for this core/queue (Phase 7.4)
            // If there's an XSK on this queue, we might want to steer there
            // For now, prioritize BPF Fast Path (redirection to TUN) 
            // BUT, if the session is flagged for Userspace (e.g. for control), use XSK
            
            // FLOW STEERING (Phase 7.4):
            // We can hash the session ID to pick a CPU core
            let _target_cpu = (session_id % 4) as u32; // Simplified steering
            
            if mode == 0 {
                inc_stat(&ctx, 6); // REDIRECT_L3
            } else {
                inc_stat(&ctx, 7); // REDIRECT_L2
            }
            return Ok(unsafe { bpf_redirect(tun_idx, 0) as u32 });
        }
    } else {
        inc_stat(&ctx, 3); // SESSION_MISSING
        
        // If session is missing, it might be a new handshake or unknown traffic.
        // Try to steer to AF_XDP for userspace handling (Phase 7.4)
        // This is the "Zero-Copy" fallback.
        if let Ok(_) = unsafe { XSK_MAP.redirect(0, 0) } {
            inc_stat(&ctx, 9); // RX_REDIRECT_XSK
            return Ok(xdp_action::XDP_REDIRECT);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
