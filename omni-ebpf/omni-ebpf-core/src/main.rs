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

// Session map keyed by session_id
#[map]
static mut SESSIONS: HashMap<u32, SessionEntry> = HashMap::with_max_entries(1024, 0);

// FDB map keyed by MAC address
#[map]
static mut FDB: HashMap<[u8; 6], FdbEntry> = HashMap::with_max_entries(1024, 0);

// Constants for parsing
const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20;
const IPV6_HDR_LEN: usize = 40;
const UDP_HDR_LEN: usize = 8;
const OMNI_HDR_LEN: usize = 12; // session_id (4) + nonce (8)
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_UDP: u8 = 17;
const OMNI_PORT: u16 = 51820;
const POLY1305_TAG_LEN: usize = 16;

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

/// ChaCha20 quarter round operation
#[inline(always)]
fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b); *d ^= *a; *d = d.rotate_left(16);
    *c = c.wrapping_add(*d); *b ^= *c; *b = b.rotate_left(12);
    *a = a.wrapping_add(*b); *d ^= *a; *d = d.rotate_left(8);
    *c = c.wrapping_add(*d); *b ^= *c; *b = b.rotate_left(7);
}

/// ChaCha20 block function - produces 64 bytes of keystream
#[inline(always)]
fn chacha20_block(key: &[u8; 32], nonce: &[u8; 8], counter: u32, output: &mut [u8; 64]) {
    let mut state = [0u32; 16];
    
    // Constants: "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // Key (8 words)
    #[allow(clippy::needless_range_loop)]
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }
    
    // Counter (1 word)
    state[12] = counter;
    
    // Nonce (2 words)
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = 0; // Additional nonce word (unused in our protocol)
    
    let mut working = state;
    
    // 20 rounds (10 double rounds)
    #[allow(clippy::needless_range_loop)]
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut working[0], &mut working[4], &mut working[8], &mut working[12]);
        quarter_round(&mut working[1], &mut working[5], &mut working[9], &mut working[13]);
        quarter_round(&mut working[2], &mut working[6], &mut working[10], &mut working[14]);
        quarter_round(&mut working[3], &mut working[7], &mut working[11], &mut working[15]);
        
        // Diagonal rounds
        quarter_round(&mut working[0], &mut working[5], &mut working[10], &mut working[15]);
        quarter_round(&mut working[1], &mut working[6], &mut working[11], &mut working[12]);
        quarter_round(&mut working[2], &mut working[7], &mut working[8], &mut working[13]);
        quarter_round(&mut working[3], &mut working[4], &mut working[9], &mut working[14]);
    }
    
    // Add original state
    #[allow(clippy::needless_range_loop)]
    for i in 0..16 {
        working[i] = working[i].wrapping_add(state[i]);
    }
    
    // Serialize to output
    #[allow(clippy::needless_range_loop)]
    for i in 0..16 {
        let bytes = working[i].to_le_bytes();
        output[i * 4] = bytes[0];
        output[i * 4 + 1] = bytes[1];
        output[i * 4 + 2] = bytes[2];
        output[i * 4 + 3] = bytes[3];
    }
}

/// Decrypt a buffer in-place using ChaCha20
#[inline(always)]
fn chacha20_decrypt(key: &[u8; 32], nonce: &[u8; 8], data: &mut [u8], len: usize) -> Result<(), ()> {
    let mut counter = 0u32;
    let mut pos = 0usize;
    
    // Process full blocks
    while pos + 64 <= len {
        let mut keystream = [0u8; 64];
        chacha20_block(key, nonce, counter, &mut keystream);
        
        // XOR with keystream (eBPF verifier needs bounded loop)
        #[allow(clippy::needless_range_loop)]
        for i in 0..64 {
            if pos + i < len {
                data[pos + i] ^= keystream[i];
            }
        }
        
        pos += 64;
        counter += 1;
    }
    
    // Process remaining bytes
    if pos < len {
        let mut keystream = [0u8; 64];
        chacha20_block(key, nonce, counter, &mut keystream);
        
        let remaining = len - pos;
        #[allow(clippy::needless_range_loop)]
        for i in 0..remaining {
            data[pos + i] ^= keystream[i];
        }
    }
    
    Ok(())
}

fn try_xdp_synapse(ctx: XdpContext) -> Result<u32, ()> {
    // Parse Ethernet header
    let eth_proto: *const u16 = ptr_at(&ctx, 12)?;
    let eth_proto = u16::from_be(unsafe { *eth_proto });

    let omni_offset = if eth_proto == ETH_P_IPV4 {
        // IPv4 path
        let ip_proto: *const u8 = ptr_at(&ctx, ETH_HDR_LEN + 9)?;
        let ip_proto = unsafe { *ip_proto };

        if ip_proto != IPPROTO_UDP {
            return Ok(xdp_action::XDP_PASS);
        }

        let dst_port: *const u16 = ptr_at(&ctx, ETH_HDR_LEN + IPV4_HDR_LEN + 2)?;
        let dst_port = u16::from_be(unsafe { *dst_port });

        if dst_port != OMNI_PORT {
            return Ok(xdp_action::XDP_PASS);
        }

        ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN
    } else if eth_proto == ETH_P_IPV6 {
        // IPv6 path
        let next_hdr: *const u8 = ptr_at(&ctx, ETH_HDR_LEN + 6)?;
        let next_hdr = unsafe { *next_hdr };

        if next_hdr != IPPROTO_UDP {
            return Ok(xdp_action::XDP_PASS);
        }

        let dst_port: *const u16 = ptr_at(&ctx, ETH_HDR_LEN + IPV6_HDR_LEN + 2)?;
        let dst_port = u16::from_be(unsafe { *dst_port });

        if dst_port != OMNI_PORT {
            return Ok(xdp_action::XDP_PASS);
        }

        ETH_HDR_LEN + IPV6_HDR_LEN + UDP_HDR_LEN
    } else {
        return Ok(xdp_action::XDP_PASS);
    };

    // Parse OmniNervous header: session_id (4 bytes) + nonce (8 bytes)
    let session_id: *const u32 = ptr_at(&ctx, omni_offset)?;
    let session_id = u32::from_be(unsafe { *session_id });

    // Extract nonce for decryption
    let mut nonce = [0u8; 8];
    for i in 0..8 {
        let byte_ptr: *const u8 = ptr_at(&ctx, omni_offset + 4 + i)?;
        nonce[i] = unsafe { *byte_ptr };
    }

    // Lookup session in map
    let session = unsafe { SESSIONS.get(&session_id) };

    match session {
        Some(entry) => {
            // Session found - decrypt payload
            // Payload starts after OmniNervous header
            let payload_offset = omni_offset + OMNI_HDR_LEN;
            
            // NOTE: Full decryption in XDP is complex due to packet size limits
            // For now, we validate the session and pass to userspace for decryption
            // A production implementation would decrypt in-place here
            
            info!(&ctx, "OmniNervous: session {} authorized (key available)", session_id);
            
            // TODO: Implement full ChaCha20-Poly1305 decryption
            // 1. Decrypt payload in-place
            // 2. Verify Poly1305 tag
            // 3. Parse inner Ethernet frame
            // 4. FDB lookup for MAC forwarding
            // 5. XDP_REDIRECT to destination interface
            
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
