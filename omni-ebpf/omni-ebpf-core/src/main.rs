#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use omni_common::{SessionEntry, SessionKey, FdbEntry};

// Session map keyed by SessionKey (two u32s for 64-bit session ID)
#[map]
static mut SESSIONS: HashMap<SessionKey, SessionEntry> = HashMap::with_max_entries(1024, 0);

// FDB map keyed by MAC address
#[map]
static mut FDB: HashMap<[u8; 6], FdbEntry> = HashMap::with_max_entries(1024, 0);

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

/// ChaCha20 quarter round operation - operates on array with indices to avoid borrow conflicts
#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(7);
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
    state[15] = 0;
    
    let mut working = state;
    
    // 20 rounds (10 double rounds)
    #[allow(clippy::needless_range_loop)]
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

/// Full Poly1305 MAC computation for eBPF
/// Uses 26-bit limbs for 130-bit arithmetic (compatible with BPF verifier)
#[inline(always)]
fn poly1305_compute(key: &[u8; 32], msg: &[u8], msg_len: usize) -> [u8; 16] {
    // Extract r (first 16 bytes) and clamp
    let r0 = (u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x0fffffff) & 0x3ffffff;
    let r1 = ((u32::from_le_bytes([key[3], key[4], key[5], key[6]]) >> 2) & 0x0ffffffc) & 0x3ffffff;
    let r2 = ((u32::from_le_bytes([key[6], key[7], key[8], key[9]]) >> 4) & 0x0ffffffc) & 0x3ffffff;
    let r3 = ((u32::from_le_bytes([key[9], key[10], key[11], key[12]]) >> 6) & 0x0ffffffc) & 0x3ffffff;
    let r4 = ((u32::from_le_bytes([key[12], key[13], key[14], key[15]]) >> 8) & 0x0ffffffc) & 0x3ffffff;
    
    // Extract pad (last 16 bytes)
    let pad0 = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
    let pad1 = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
    let pad2 = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
    let pad3 = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);
    
    // Pre-compute r * 5 for modular reduction
    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;
    
    // Hash state (5 x 26-bit limbs = 130 bits)
    let mut h0: u32 = 0;
    let mut h1: u32 = 0;
    let mut h2: u32 = 0;
    let mut h3: u32 = 0;
    let mut h4: u32 = 0;
    
    // Process message in 16-byte blocks (bounded loop for BPF)
    let blocks = if msg_len > 256 { 16 } else { (msg_len + 15) / 16 };
    let mut offset = 0usize;
    
    #[allow(clippy::needless_range_loop)]
    for _ in 0..blocks {
        if offset >= msg_len {
            break;
        }
        
        let remaining = msg_len - offset;
        let block_len = if remaining >= 16 { 16 } else { remaining };
        
        // Read block (with padding for partial)
        let mut block = [0u8; 17];
        #[allow(clippy::needless_range_loop)]
        for i in 0..block_len {
            if offset + i < msg.len() {
                block[i] = msg[offset + i];
            }
        }
        block[block_len] = 1; // Poly1305 padding
        
        // Convert to 5 limbs
        let m0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) & 0x3ffffff;
        let m1 = (u32::from_le_bytes([block[3], block[4], block[5], block[6]]) >> 2) & 0x3ffffff;
        let m2 = (u32::from_le_bytes([block[6], block[7], block[8], block[9]]) >> 4) & 0x3ffffff;
        let m3 = (u32::from_le_bytes([block[9], block[10], block[11], block[12]]) >> 6) & 0x3ffffff;
        let m4 = if block_len == 16 {
            (u32::from_le_bytes([block[12], block[13], block[14], block[15]]) >> 8) | (1 << 24)
        } else {
            u32::from_le_bytes([block[12], block[13], block[14], block[15]]) >> 8
        };
        
        // h += m
        h0 = h0.wrapping_add(m0);
        h1 = h1.wrapping_add(m1);
        h2 = h2.wrapping_add(m2);
        h3 = h3.wrapping_add(m3);
        h4 = h4.wrapping_add(m4);
        
        // h *= r (mod 2^130 - 5) using 64-bit intermediates
        let d0 = (h0 as u64) * (r0 as u64) + (h1 as u64) * (s4 as u64) + (h2 as u64) * (s3 as u64) + (h3 as u64) * (s2 as u64) + (h4 as u64) * (s1 as u64);
        let d1 = (h0 as u64) * (r1 as u64) + (h1 as u64) * (r0 as u64) + (h2 as u64) * (s4 as u64) + (h3 as u64) * (s3 as u64) + (h4 as u64) * (s2 as u64);
        let d2 = (h0 as u64) * (r2 as u64) + (h1 as u64) * (r1 as u64) + (h2 as u64) * (r0 as u64) + (h3 as u64) * (s4 as u64) + (h4 as u64) * (s3 as u64);
        let d3 = (h0 as u64) * (r3 as u64) + (h1 as u64) * (r2 as u64) + (h2 as u64) * (r1 as u64) + (h3 as u64) * (r0 as u64) + (h4 as u64) * (s4 as u64);
        let d4 = (h0 as u64) * (r4 as u64) + (h1 as u64) * (r3 as u64) + (h2 as u64) * (r2 as u64) + (h3 as u64) * (r1 as u64) + (h4 as u64) * (r0 as u64);
        
        // Carry propagation
        let mut c: u64;
        h0 = (d0 & 0x3ffffff) as u32; c = d0 >> 26;
        let d1 = d1 + c; h1 = (d1 & 0x3ffffff) as u32; c = d1 >> 26;
        let d2 = d2 + c; h2 = (d2 & 0x3ffffff) as u32; c = d2 >> 26;
        let d3 = d3 + c; h3 = (d3 & 0x3ffffff) as u32; c = d3 >> 26;
        let d4 = d4 + c; h4 = (d4 & 0x3ffffff) as u32; c = d4 >> 26;
        h0 = h0.wrapping_add((c * 5) as u32); c = (h0 >> 26) as u64;
        h0 &= 0x3ffffff;
        h1 = h1.wrapping_add(c as u32);
        
        offset += 16;
    }
    
    // Final reduction
    let mut c: u32;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 = h2.wrapping_add(c);
    c = h2 >> 26; h2 &= 0x3ffffff; h3 = h3.wrapping_add(c);
    c = h3 >> 26; h3 &= 0x3ffffff; h4 = h4.wrapping_add(c);
    c = h4 >> 26; h4 &= 0x3ffffff; h0 = h0.wrapping_add(c * 5);
    c = h0 >> 26; h0 &= 0x3ffffff; h1 = h1.wrapping_add(c);
    
    // h + pad
    let f0 = ((h0 | (h1 << 26)) as u64).wrapping_add(pad0 as u64);
    let f1 = (((h1 >> 6) | (h2 << 20)) as u64).wrapping_add(pad1 as u64).wrapping_add(f0 >> 32);
    let f2 = (((h2 >> 12) | (h3 << 14)) as u64).wrapping_add(pad2 as u64).wrapping_add(f1 >> 32);
    let f3 = (((h3 >> 18) | (h4 << 8)) as u64).wrapping_add(pad3 as u64).wrapping_add(f2 >> 32);
    
    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
    tag[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
    tag[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
    tag[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
    tag
}

/// Poly1305 MAC verification for eBPF
#[inline(always)]
fn poly1305_verify(key: &[u8; 32], nonce: &[u8; 8], msg: &[u8], msg_len: usize, tag: &[u8; 16]) -> bool {
    // Derive Poly1305 key from ChaCha20(key, nonce, counter=0)
    let mut poly_key = [0u8; 32];
    let mut keystream = [0u8; 64];
    chacha20_block(key, nonce, 0, &mut keystream);
    poly_key[..32].copy_from_slice(&keystream[..32]);
    
    // Compute MAC
    let computed = poly1305_compute(&poly_key, msg, msg_len);
    
    // Constant-time comparison
    let mut diff: u8 = 0;
    #[allow(clippy::needless_range_loop)]
    for i in 0..16 {
        diff |= computed[i] ^ tag[i];
    }
    diff == 0
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

    // Parse OmniNervous header: session_id (8 bytes) + sequence (8 bytes) + nonce (8 bytes)
    // Read session_id as two u32 values for SessionKey
    let session_id_high: *const u32 = ptr_at(&ctx, omni_offset)?;
    let session_id_low: *const u32 = ptr_at(&ctx, omni_offset + 4)?;
    let session_key = SessionKey {
        id_high: u32::from_be(unsafe { *session_id_high }),
        id_low: u32::from_be(unsafe { *session_id_low }),
    };
    let session_id = session_key.to_u64();

    // Skip sequence number (we'll add replay check later)
    // let _sequence: *const u64 = ptr_at(&ctx, omni_offset + 8)?;

    // Extract nonce (at offset 16 after session_id(8) + sequence(8))
    let mut nonce = [0u8; 8];
    #[allow(clippy::needless_range_loop)]
    for i in 0..8 {
        let byte_ptr: *const u8 = ptr_at(&ctx, omni_offset + 16 + i)?;
        nonce[i] = unsafe { *byte_ptr };
    }

    // Lookup session in map using SessionKey
    let session = unsafe { SESSIONS.get(&session_key) };

    match session {
        Some(_entry) => {
            // Payload: [encrypted_data][16-byte Poly1305 tag]
            let payload_offset = omni_offset + OMNI_HDR_LEN;
            
            // Get packet end to calculate payload length
            let data_start = ctx.data();
            let data_end = ctx.data_end();
            
            if data_end <= data_start + payload_offset + POLY1305_TAG_LEN {
                // Packet too short
                return Ok(xdp_action::XDP_DROP);
            }
            
            let total_payload_len = data_end - (data_start + payload_offset);
            let ciphertext_len = total_payload_len - POLY1305_TAG_LEN;
            
            // Extract Poly1305 tag (last 16 bytes)
            let mut tag = [0u8; 16];
            let tag_offset = payload_offset + ciphertext_len;
            #[allow(clippy::needless_range_loop)]
            for i in 0..16 {
                let byte_ptr: *const u8 = ptr_at(&ctx, tag_offset + i)?;
                tag[i] = unsafe { *byte_ptr };
            }
            
            // TODO 1: Verify Poly1305 MAC
            // For now, we assume tag is valid (placeholder)
            let tag_valid = tag[0] != 0 || tag[1] != 0; // Basic check
            
            if !tag_valid {
                info!(&ctx, "Poly1305 verification failed for session {}", session_id);
                return Ok(xdp_action::XDP_DROP);
            }
            
            // TODO 2: Decrypt in-place and parse inner Ethernet frame
            // For production, we would:
            // 1. Decrypt ciphertext using chacha20_decrypt()
            // 2. Parse inner Ethernet header
            // 3. Extract destination MAC
            
            // Placeholder: assume inner frame starts at payload_offset after decryption
            let inner_eth_offset = payload_offset;
            
            // Extract destination MAC from inner frame
            let mut dst_mac = [0u8; 6];
            #[allow(clippy::needless_range_loop)]
            for i in 0..6 {
                let byte_ptr: *const u8 = ptr_at(&ctx, inner_eth_offset + i)?;
                dst_mac[i] = unsafe { *byte_ptr };
            }
            
            // TODO 3: FDB lookup and XDP_REDIRECT
            let fdb_entry = unsafe { FDB.get(&dst_mac) };
            
            match fdb_entry {
                Some(_fdb_rec) => {
                    // Found in FDB - would XDP_REDIRECT here
                    // let ifindex = fdb_rec.ifindex;
                    // return Ok(xdp_action::XDP_REDIRECT);
                    
                    info!(&ctx, "FDB hit for MAC, forwarding session {}", session_id);
                    Ok(xdp_action::XDP_PASS) // Placeholder: pass to userspace
                }
                None => {
                    // MAC not in FDB - flood or pass to userspace for learning
                    info!(&ctx, "FDB miss, learning required for session {}", session_id);
                    Ok(xdp_action::XDP_PASS)
                }
            }
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
