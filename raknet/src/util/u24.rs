pub const MASK: u32 = 0x00FF_FFFF;
const MODULUS: i64 = 1 << 24;
const HALF: u32 = 0x0080_0000;

pub fn add(value: u32, n: u32) -> u32 {
    value.wrapping_add(n) & MASK
}

pub fn distance(from: u32, to: u32) -> i32 {
    let forward = to.wrapping_sub(from) & MASK;
    if forward >= HALF {
        (forward as i64 - MODULUS) as i32
    } else {
        forward as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_wraps_past_the_top_of_the_range() {
        assert_eq!(add(MASK, 1), 0);
        assert_eq!(add(MASK - 1, 3), 1);
    }

    #[test]
    fn distance_is_signed_across_the_wrap() {
        assert_eq!(distance(MASK, 0), 1);
        assert_eq!(distance(0, MASK), -1);
        assert_eq!(distance(5, 5), 0);
        assert_eq!(distance(10, 2), -8);
    }
}
