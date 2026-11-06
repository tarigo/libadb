pub(crate) fn format_u32(mut n: u32, out: &mut [u8; 10]) -> &[u8] {
    if n == 0 {
        out[9] = b'0';
        return &out[9..];
    }
    let mut pos = 10;
    while n > 0 {
        pos -= 1;
        out[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &out[pos..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_u32_zero() {
        let mut buf = [0u8; 10];
        assert_eq!(format_u32(0, &mut buf), b"0");
    }

    #[test]
    fn format_u32_typical_mode() {
        let mut buf = [0u8; 10];
        assert_eq!(format_u32(33188, &mut buf), b"33188");
    }

    #[test]
    fn format_u32_max() {
        let mut buf = [0u8; 10];
        assert_eq!(format_u32(u32::MAX, &mut buf), b"4294967295");
    }

    #[test]
    fn format_u32_single_digit() {
        let mut buf = [0u8; 10];
        assert_eq!(format_u32(7, &mut buf), b"7");
    }
}
