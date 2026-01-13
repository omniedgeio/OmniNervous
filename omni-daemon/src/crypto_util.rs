/// Constant-time comparison for cryptographic values
/// Prevents timing attacks by ensuring comparison always takes same time
#[inline(always)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    
    result == 0
}

/// Constant-time comparison for 16-byte arrays (Poly1305 tags)
#[inline(always)]
pub fn constant_time_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut result = 0u8;
    for i in 0..16 {
        result |= a[i] ^ b[i];
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_constant_time_eq_16() {
        let a = [1u8; 16];
        let b = [1u8; 16];
        let mut c = [1u8; 16];
        c[15] = 2;
        
        assert!(constant_time_eq_16(&a, &b));
        assert!(!constant_time_eq_16(&a, &c));
    }
}
