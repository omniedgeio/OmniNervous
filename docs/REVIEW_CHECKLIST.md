# OmniNervous Review Checklist

## How to Use This Checklist

Review each section in order. Mark items as:
- `[ ]` Not reviewed
- `[/]` In progress / needs work
- `[x]` Verified working

---

## 1. Signaling Protocol (Nucleus ↔ Edge)

### 1.1 Message Flow
- [ ] `REGISTER` → `REGISTER_ACK` parses correctly
- [ ] `HEARTBEAT` → `HEARTBEAT_ACK` returns delta (new + removed peers)
- [ ] `QUERY_PEER` → `PEER_INFO` returns correct peer info
- [ ] Signaling messages use types 0x01-0x07 (< 0x10)

### 1.2 Nucleus State
- [ ] `NucleusState` uses HashMap for O(1) VIP lookup
- [ ] `register()` adds peer with correct `joined_at` timestamp
- [ ] `heartbeat()` returns delta since last heartbeat
- [ ] `cleanup()` removes peers after 60s timeout
- [ ] `query_peer()` returns correct peer for VIP

### 1.3 Edge Client
- [ ] `NucleusClient::new()` resolves nucleus address
- [ ] `register()` sends correct CBOR-encoded message
- [ ] `heartbeat()` includes peer count
- [ ] `query_peer()` sends QUERY_PEER for unknown VIP

**Files**: `signaling.rs`, `main.rs:310-346`

---

## 2. Peer Discovery & Routing

### 2.1 Peer Table
- [ ] `PeerInfo` has: session_id, endpoint, virtual_ip, public_key, last_seen
- [ ] `register()` stores public key for handshake
- [ ] `peers_needing_handshake()` returns peers with pubkey but no handshake
- [ ] `mark_handshake_initiated()` prevents duplicate handshakes
- [ ] `remove_by_vip()` handles peer departure
- [ ] `lookup_by_vip()` returns correct peer
- [ ] `lookup_by_session()` returns correct peer

**Files**: `peers.rs`

---

## 3. Noise Handshake (P2P Security)

### 3.1 Noise Protocol
- [ ] Pattern: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` (with PSK)
- [ ] Pattern: `Noise_IK_25519_ChaChaPoly_BLAKE2s` (without PSK)
- [ ] `new_initiator()` requires remote public key
- [ ] `new_responder()` uses local private key only
- [ ] `process_handshake_with_payload()` returns peer VIP

### 3.2 Handshake Flow
- [ ] Initiator sends VIP in handshake payload
- [ ] Responder extracts peer VIP from payload
- [ ] Handshake completes after 2 round trips
- [ ] `finalize_session()` transitions to Active state

**Files**: `noise.rs`, `session.rs`

---

## 4. Session Management

### 4.1 Session IDs
- [ ] Both sides use SAME session_id (from initiator's packet header)
- [ ] Responder uses `client_session_id` not `generate_session_id()`
- [ ] Session stored in HashMap with correct state

### 4.2 Session States
- [ ] `Handshaking(NoiseSession)` during handshake
- [ ] `Active(StatelessTransportState)` after finalization
- [ ] `advance_handshake()` returns response + peer payload
- [ ] `finalize_session()` converts to transport state

**Files**: `session.rs`, `main.rs:615-680`

---

## 5. TUN Interface & Packet Flow

### 5.1 TUN Setup
- [ ] TUN interface created with name "omni0"
- [ ] VIP assigned correctly
- [ ] MTU set appropriately
- [ ] Platform-specific (macOS utun, Linux tun)

### 5.2 Outbound (TUN → UDP)
- [ ] Extract destination IP from packet (bytes 16-19)
- [ ] Lookup peer by VIP in peer_table
- [ ] Get active session for peer
- [ ] Encrypt with ChaCha20-Poly1305
- [ ] Send: [session_id(8)] [encrypted_payload]

### 5.3 Inbound (UDP → TUN)
- [ ] Parse session_id from first 8 bytes
- [ ] Lookup active session
- [ ] Decrypt payload
- [ ] Write to TUN interface

### 5.4 On-Demand Discovery
- [ ] Unknown destination VIP triggers `query_peer()`
- [ ] First packet dropped, subsequent packets routed

**Files**: `tun.rs`, `main.rs:451-507`, `main.rs:680-720`

---

## 6. Security Features

### 6.1 Cryptography
- [ ] PSK derived from cluster + secret via SHA-256
- [ ] Secret minimum 16 characters enforced
- [ ] X25519 key exchange
- [ ] ChaCha20-Poly1305 AEAD encryption
- [ ] 64-bit session IDs via HMAC

### 6.2 Rate Limiting
- [ ] Max sessions per IP per second
- [ ] Handshake timeout
- [ ] Session expiration

### 6.3 Identity
- [ ] Ed25519 keypair generation
- [ ] Keys stored in `~/.omniedge/identity.json`
- [ ] Public key used in signaling registration

**Files**: `noise.rs`, `identity.rs`, `ratelimit.rs`

---

## 7. eBPF/XDP Integration

### 7.1 eBPF Program
- [ ] ChaCha20 decryption in XDP
- [ ] Poly1305 MAC verification
- [ ] Session map lookup
- [ ] FDB forwarding

### 7.2 BPF Sync
- [ ] Session map sync between userspace and eBPF
- [ ] `insert_session()` updates BPF map
- [ ] `remove_session()` cleans BPF map

**Files**: `bpf_sync.rs`, `omni-ebpf-core/`

---

## 8. WHITEPAPER Accuracy

### 8.1 Architecture Claims
- [ ] Dual-plane design (Ganglion + Synapse) described
- [ ] Nucleus as signaling server (not relay) is accurate
- [ ] Protocol stack diagram matches implementation

### 8.2 Scalability Claims
- [ ] "1000+ edges per cluster" - verified by delta protocol
- [ ] O(1) VIP lookup - verified by HashMap
- [ ] Bandwidth analysis (delta vs push) - math is correct

### 8.3 Performance Claims
- [ ] XDP latency claims marked as "projected"
- [ ] Throughput claims marked as "TBD" or with caveats
- [ ] Robotics use case requirements listed as targets

**Files**: `docs/WHITEPAPER.md`

---

## 9. CI/Testing

### 9.1 Unit Tests
- [ ] `cargo test -p omni-daemon` passes
- [ ] Noise handshake tests
- [ ] PSK derivation tests
- [ ] Peer table tests

### 9.2 Integration Tests
- [ ] Docker network setup correct
- [ ] Nucleus container starts successfully
- [ ] Edge containers register with Nucleus
- [ ] VPN ping test passes
- [ ] Wait time sufficient for heartbeat cycle (35s)

**Files**: `.github/workflows/test.yml`

---

## 10. Outstanding Issues

### 10.1 Known Gaps
- [ ] BPF key extraction from transport state (TODO in code)
- [ ] Relay fallback not implemented (mentioned in docs but not code)
- [ ] PMTUD not implemented

### 10.2 Security Review Needed
- [ ] Session ID spoofing protection
- [ ] Replay attack protection
- [ ] DoS resistance (rate limiting verified)

---

## Review Sign-off

| Reviewer | Date | Sections Reviewed | Notes |
|:---|:---|:---|:---|
| | | | |

---

*Last updated: 2026-01-14*
