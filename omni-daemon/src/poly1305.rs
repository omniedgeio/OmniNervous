/// Production-ready Poly1305 MAC implementation
/// RFC 8439 compliant with constant-time operations

/// Poly1305 state for incremental MAC computation
pub struct Poly1305 {
    r: [u32; 5],      // Accumulator r (clamped key)
    h: [u32; 5],      // Running hash state
    pad: [u32; 4],    // Pad value from key
    leftover: usize,  // Bytes in buffer
    buffer: [u8; 16], // Partial block buffer
    final_called: bool,
}

impl Poly1305 {
    /// Initialize Poly1305 with 32-byte key
    /// First 16 bytes: r (clamped), Last 16 bytes: pad
    pub fn new(key: &[u8; 32]) -> Self {
        let mut poly = Self {
            r: [0u32; 5],
            h: [0u32; 5],
            pad: [0u32; 4],
            leftover: 0,
            buffer: [0u8; 16],
            final_called: false,
        };

        // Extract r (first 16 bytes) and clamp it
        poly.r[0] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x0fffffff;
        poly.r[1] = u32::from_le_bytes([key[4], key[5], key[6], key[7]]) & 0x0ffffffc;
        poly.r[2] = u32::from_le_bytes([key[8], key[9], key[10], key[11]]) & 0x0ffffffc;
        poly.r[3] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]) & 0x0ffffffc;
        
        // Extract pad (last 16 bytes)
        poly.pad[0] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        poly.pad[1] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        poly.pad[2] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        poly.pad[3] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);

        poly
    }

    /// Process a single 16-byte block
    #[inline(always)]
    fn block(&mut self, msg: &[u8], flag: u32) {
        // Convert block to 5 limbs (26-bit each for 130-bit arithmetic)
        let mut m = [0u32; 5];
        m[0] = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]) & 0x3ffffff;
        m[1] = (u32::from_le_bytes([msg[3], msg[4], msg[5], msg[6]]) >> 2) & 0x3ffffff;
        m[2] = (u32::from_le_bytes([msg[6], msg[7], msg[8], msg[9]]) >> 4) & 0x3ffffff;
        m[3] = (u32::from_le_bytes([msg[9], msg[10], msg[11], msg[12]]) >> 6) & 0x3ffffff;
        m[4] = (u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]) >> 8) | (flag << 24);

        // h += m
        let mut h0 = self.h[0] as u64 + m[0] as u64;
        let mut h1 = self.h[1] as u64 + m[1] as u64;
        let mut h2 = self.h[2] as u64 + m[2] as u64;
        let mut h3 = self.h[3] as u64 + m[3] as u64;
        let mut h4 = self.h[4] as u64 + m[4] as u64;

        // h *= r (modulo 2^130 - 5)
        let r0 = self.r[0] as u64;
        let r1 = self.r[1] as u64;
        let r2 = self.r[2] as u64;
        let r3 = self.r[3] as u64;
        let r4 = self.r[4] as u64;

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        // Propagate carries
        let mut c: u64;
        c = d0 >> 26; d0 &= 0x3ffffff; d1 += c;
        c = d1 >> 26; d1 &= 0x3ffffff; d2 += c;
        c = d2 >> 26; d2 &= 0x3ffffff; d3 += c;
        c = d3 >> 26; d3 &= 0x3ffffff; d4 += c;
        c = d4 >> 26; d4 &= 0x3ffffff; d0 += c * 5;
        c = d0 >> 26; d0 &= 0x3ffffff; d1 += c;

        self.h[0] = d0 as u32;
        self.h[1] = d1 as u32;
        self.h[2] = d2 as u32;
        self.h[3] = d3 as u32;
        self.h[4] = d4 as u32;
    }

    /// Update MAC with message data
    pub fn update(&mut self, data: &[u8]) {
        let mut m = data;

        // Handle leftover from previous update
        if self.leftover > 0 {
            let want = 16 - self.leftover;
            let have = m.len().min(want);
            self.buffer[self.leftover..self.leftover + have].copy_from_slice(&m[..have]);
            m = &m[have..];
            self.leftover += have;

            if self.leftover < 16 {
                return;
            }

            // Copy buffer to avoid simultaneous borrow
            let block_data = self.buffer;
            self.block(&block_data, 1);
            self.leftover = 0;
        }

        // Process full blocks
        while m.len() >= 16 {
            self.block(&m[..16], 1);
            m = &m[16..];
        }

        // Save remainder
        if !m.is_empty() {
            self.buffer[..m.len()].copy_from_slice(m);
            self.leftover = m.len();
        }
    }

    /// Finalize MAC and produce 16-byte tag
    pub fn finalize(&mut self) -> [u8; 16] {
        if self.final_called {
            panic!("Poly1305::finalize called twice");
        }
        self.final_called = true;

        // Process final block if any
        if self.leftover > 0 {
            let mut block = [0u8; 16];
            block[..self.leftover].copy_from_slice(&self.buffer[..self.leftover]);
            block[self.leftover] = 1; // Padding
            self.block(&block, 0);
        }

        // Fully reduce modulo 2^130 - 5
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c: u32;
        c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
        c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
        c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
        c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

        // Compute h - (2^130 - 5)
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26; g0 &= 0x3ffffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26; g1 &= 0x3ffffff;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26; g2 &= 0x3ffffff;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26; g3 &= 0x3ffffff;
        let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // Select h if g >= 2^130, else select g
        let mask = (g4 >> 31).wrapping_sub(1);
        g0 &= mask; h0 = (h0 & !mask) | g0;
        g1 &= mask; h1 = (h1 & !mask) | g1;
        g2 &= mask; h2 = (h2 & !mask) | g2;
        g3 &= mask; h3 = (h3 & !mask) | g3;
        g4 &= mask; h4 = (h4 & !mask) | g4;

        // h = (h + pad) mod 2^128
        let mut f0 = ((h0 | (h1 << 26)) as u64).wrapping_add(self.pad[0] as u64);
        let mut f1 = ((h1 >> 6) | (h2 << 20)) as u64 + self.pad[1] as u64 + (f0 >> 32);
        let mut f2 = ((h2 >> 12) | (h3 << 14)) as u64 + self.pad[2] as u64 + (f1 >> 32);
        let mut f3 = ((h3 >> 18) | (h4 << 8)) as u64 + self.pad[3] as u64 + (f2 >> 32);

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
        tag[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
        tag[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
        tag[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());

        tag
    }

    /// One-shot MAC computation
    pub fn compute(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
        let mut poly = Self::new(key);
        poly.update(msg);
        poly.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly1305_rfc8439() {
        // Test vector from RFC 8439 Section 2.5.2
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];
        
        let msg = b"Cryptographic Forum Research Group";
        
        let tag = Poly1305::compute(&key, msg);
        
        let expected = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
        ];
        
        assert_eq!(tag, expected, "Poly1305 RFC 8439 test failed");
    }
}
