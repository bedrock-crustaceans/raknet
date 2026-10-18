use crate::util::u24;

pub type Range = (u32, u32);

pub fn contains(ranges: &[Range], base: u32, index: u32) -> bool {
    let target = u24::distance(base, index);
    let pos = ranges.partition_point(|&(start, _)| u24::distance(base, start) <= target);
    pos.checked_sub(1)
        .and_then(|prev| ranges.get(prev))
        .is_some_and(|&(start, len)| u24::distance(start, index) < len as i32)
}

pub fn insert(ranges: &mut Vec<Range>, base: u32, index: u32) -> bool {
    let target = u24::distance(base, index);
    let pos = ranges.partition_point(|&(start, _)| u24::distance(base, start) <= target);

    if let Some(&(start, len)) = pos.checked_sub(1).and_then(|prev| ranges.get(prev)) {
        let offset = u24::distance(start, index);
        if offset < len as i32 {
            return false;
        }
        if offset == len as i32 {
            ranges[pos - 1].1 += 1;
            let end = u24::add(start, ranges[pos - 1].1);
            if ranges.get(pos).is_some_and(|&(next, _)| next == end) {
                let (_, next_len) = ranges.remove(pos);
                ranges[pos - 1].1 += next_len;
            }
            return true;
        }
    }

    if let Some(next) = ranges.get_mut(pos)
        && next.0 == u24::add(index, 1)
    {
        next.0 = index;
        next.1 += 1;
        return true;
    }

    ranges.insert(pos, (index, 1));
    true
}

pub fn take_contiguous(ranges: &mut Vec<Range>, base: u32) -> u32 {
    match ranges.first() {
        Some(&(start, len)) if start == base => {
            ranges.remove(0);
            u24::add(base, len)
        }
        _ => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjacent_indexes_merge_into_one_range() {
        let mut ranges = Vec::new();

        for index in [5, 6, 7] {
            assert!(insert(&mut ranges, 0, index));
        }

        assert_eq!(ranges, vec![(5, 3)]);
    }

    #[test]
    fn an_index_bridging_two_ranges_joins_them() {
        let mut ranges = Vec::new();

        for index in [3, 5, 4] {
            assert!(insert(&mut ranges, 0, index));
        }

        assert_eq!(ranges, vec![(3, 3)]);
    }

    #[test]
    fn prepending_extends_the_following_range() {
        let mut ranges = Vec::new();

        insert(&mut ranges, 0, 6);
        insert(&mut ranges, 0, 5);

        assert_eq!(ranges, vec![(5, 2)]);
    }

    #[test]
    fn contains_finds_indexes_inside_ranges_only() {
        let ranges = vec![(5, 3), (10, 1)];

        assert!([5, 6, 7, 10].iter().all(|&i| contains(&ranges, 0, i)));
        assert!([4, 8, 9, 11].iter().all(|&i| !contains(&ranges, 0, i)));
    }

    #[test]
    fn repeated_indexes_are_not_new() {
        let mut ranges = Vec::new();

        insert(&mut ranges, 0, 4);
        insert(&mut ranges, 0, 5);

        assert!(!insert(&mut ranges, 0, 4));
        assert!(!insert(&mut ranges, 0, 5));
        assert_eq!(ranges, vec![(4, 2)]);
    }

    #[test]
    fn ranges_stay_ordered_across_counter_wraparound() {
        let base = u24::MASK - 2;
        let mut ranges = Vec::new();

        for index in [1, u24::MASK, 0, 4] {
            assert!(insert(&mut ranges, base, index));
        }

        assert_eq!(ranges, vec![(u24::MASK, 3), (4, 1)]);
    }

    #[test]
    fn take_contiguous_consumes_a_range_starting_at_the_base() {
        let mut ranges = vec![(5, 3), (10, 1)];

        assert_eq!(take_contiguous(&mut ranges, 4), 4);
        assert_eq!(take_contiguous(&mut ranges, 5), 8);
        assert_eq!(ranges, vec![(10, 1)]);
    }
}
